# rule_engine.py
import fnmatch
import json
import logging
import time
import uuid
from pathlib import Path

import yaml
import jsonschema

from alerter import build_alert
from state_manager import StateManager
from yara_scanner import YaraScanner

logger = logging.getLogger(__name__)

# Chemin vers le schéma de validation des règles YAML
_RULE_SCHEMA_PATH = Path(__file__).parent.parent / "docs" / "rule-schema.json"


class RuleEngine:
    """Évalue les événements normalisés contre les règles YAML chargées.

    Supporte 4 types de règles :
    - Type 1 : seuil simple (count_events >= threshold)
    - Type 2 : étapes séquentielles (kill-chain stateful)
    - Type 3 : cooccurrence multi-sources (sans ordre)
    - Type 4 : détection YARA directe (samba_write + yara_match)

    Les règles invalides sont loggées et ignorées — pas de crash.

    Attributes:
        state: StateManager injecté depuis main.py.
        yara: YaraScanner injecté depuis main.py.
        rules: Liste des règles YAML chargées et validées.
    """

    def __init__(
        self,
        state_manager: StateManager,
        yara_scanner: YaraScanner,
        rules_dir: str,
    ) -> None:
        """Charge et valide les règles YAML au démarrage.

        Args:
            state_manager: Instance StateManager partagée (injection de dépendance).
            yara_scanner: Instance YaraScanner partagée.
            rules_dir: Chemin vers engine/rules/attack/.
        """
        self.state   = state_manager
        self.yara    = yara_scanner
        self.rules: list[dict] = []
        self._schema = self._load_rule_schema()
        self._load_rules(rules_dir)

    # ------------------------------------------------------------------
    # Interface publique
    # ------------------------------------------------------------------

    def process_event(self, event: dict) -> list[dict] | None:
        """Évalue l'événement contre toutes les règles chargées.

        Args:
            event: Événement normalisé conforme au schéma EventNormalized.

        Returns:
            Liste d'alertes déclenchées (peut être vide si aucune règle
            ne matche), ou None pour signaler l'absence d'alerte.
        """
        alerts: list[dict] = []

        for rule in self.rules:
            rule_type = rule.get("type")
            # Filtrage rapide par source_host_pattern au niveau règle
            pattern = rule.get("source_host_pattern", "*")
            if not fnmatch.fnmatch(event.get("source_host", ""), pattern):
                continue

            try:
                if rule_type == 1:
                    alert = self._eval_type1(rule, event)
                elif rule_type == 2:
                    alert = self._eval_type2(rule, event)
                elif rule_type == 3:
                    alert = self._eval_type3(rule, event)
                elif rule_type == 4:
                    alert = self._eval_type4(rule, event)
                else:
                    alert = None
            except Exception as exc:  # pragma: no cover
                logger.error("Erreur évaluation règle %s : %s", rule.get("rule_id"), exc)
                alert = None

            if alert:
                alerts.append(alert)

        return alerts if alerts else None

    # ------------------------------------------------------------------
    # Évaluateurs par type
    # ------------------------------------------------------------------

    def _eval_type1(self, rule: dict, event: dict) -> dict | None:
        """Évalue une règle Type 1 : seuil simple.

        Compte les événements du type configuré dans la fenêtre temporelle
        pour la valeur du champ group_by. Déclenche si count >= threshold.

        Args:
            rule: Règle YAML chargée.
            event: Événement courant normalisé.

        Returns:
            Dict alerte si le seuil est atteint, None sinon.
        """
        trigger    = rule["trigger"]
        event_type = trigger["event_type"]
        threshold  = trigger["threshold"]
        window_s   = trigger["window_seconds"]
        group_by   = trigger["group_by"]

        # L'événement courant doit correspondre au type attendu
        if event.get("event_type") != event_type:
            return None

        group_value = event.get(group_by)
        if group_value is None:
            return None

        # Filtres optionnels (ex: http_status pour WEB_BRUTEFORCE)
        filters = trigger.get("filter", {})
        if filters:
            if not self._check_extra_filter(event, filters):
                return None

        count = self.state.count_events(event_type, group_value, group_by, window_s)
        if count < threshold:
            return None

        # Récupérer les événements pour l'alerte
        events = self.state.get_events(event_type, group_value, group_by, window_s)
        return build_alert(
            rule=rule,
            events=events,
            attacker_ip=event.get("actor_ip"),
            target_host=event.get("source_host", ""),
            target_ip="",
            yara_match=None,
        )

    def _eval_type2(self, rule: dict, event: dict) -> dict | None:
        """Évalue une règle Type 2 : étapes séquentielles (machine à états).

        Vérifie si l'événement courant fait progresser ou complète
        une séquence d'attaque (kill-chain). L'état est persisté dans
        la table 'contexts' du StateManager.

        Args:
            rule: Règle YAML avec champ 'steps'.
            event: Événement courant normalisé.

        Returns:
            Dict alerte si toutes les étapes sont complètes, None sinon.
        """
        rule_id = rule["rule_id"]
        steps   = rule["steps"]

        # Trouver le step courant qui correspond à l'event
        for step_def in steps:
            step_num   = step_def["step"]
            step_type  = step_def["event_type"]
            step_pat   = step_def.get("source_host_pattern", "*")

            if event.get("event_type") != step_type:
                continue
            if not fnmatch.fnmatch(event.get("source_host", ""), step_pat):
                continue

            if step_num == 1:
                # Step 1 : vérifier les conditions initiales
                cond = step_def.get("condition", {})
                if cond.get("yara_match") == "required" and event.get("yara_match") is None:
                    continue

                # Créer ou réinitialiser le contexte
                actor_ip   = event.get("actor_ip")
                actor_user = event.get("actor_user")
                self.state.set_context(
                    rule_id=rule_id,
                    actor_ip=actor_ip,
                    actor_user=actor_user,
                    step=1,
                    extra={"step1_event": self._slim_event(event)},
                )
                logger.debug("[%s] Contexte step 1 créé pour ip=%s user=%s",
                             rule_id, actor_ip, actor_user)

            else:
                # Step N>1 : chercher un contexte existant au step N-1
                match_on = step_def.get("match_on", "actor_ip")
                match_value = event.get(match_on)
                if match_value is None:
                    continue

                # Résoudre l'IP et le user selon le champ de corrélation
                actor_ip   = event.get("actor_ip") if match_on == "actor_ip" else None
                actor_user = event.get("actor_user") if match_on == "actor_user" else None

                ctx = self.state.get_context(rule_id, actor_ip, actor_user)
                if ctx is None or ctx.get("step") != step_num - 1:
                    continue

                # Vérifier la fenêtre temporelle
                window_s = step_def.get("window_seconds", 3600)
                last_seen_s = ctx["last_seen"] / 1000
                if time.time() - last_seen_s > window_s:
                    # Contexte expiré — on le supprime
                    self.state.delete_context(rule_id, actor_ip, actor_user)
                    continue

                # Vérifier yara_match requis sur le step précédent
                cond = step_def.get("condition", {})
                if cond.get("yara_match") == "required":
                    step1_event = (ctx.get("extra") or {}).get("step1_event", {})
                    if not step1_event.get("yara_match"):
                        continue

                if step_num == len(steps):
                    # Dernière étape → déclencher l'alerte
                    extra_ctx = ctx.get("extra") or {}
                    step1_event = extra_ctx.get("step1_event", {})
                    yara_match  = step1_event.get("yara_match") if step1_event else None

                    # Supprimer le contexte — la chaîne est terminée
                    self.state.delete_context(rule_id, actor_ip, actor_user)

                    return build_alert(
                        rule=rule,
                        events=[step1_event, self._slim_event(event)] if step1_event else [self._slim_event(event)],
                        attacker_ip=event.get("actor_ip"),
                        target_host=event.get("source_host", ""),
                        target_ip="",
                        yara_match=yara_match,
                    )
                else:
                    # Avancer au step suivant
                    existing_extra = ctx.get("extra") or {}
                    existing_extra[f"step{step_num}_event"] = self._slim_event(event)
                    self.state.set_context(
                        rule_id=rule_id,
                        actor_ip=actor_ip,
                        actor_user=actor_user,
                        step=step_num,
                        extra=existing_extra,
                    )

        return None

    def _eval_type3(self, rule: dict, event: dict) -> dict | None:
        """Évalue une règle Type 3 : cooccurrence multi-sources.

        Vérifie que tous les event_types requis sont présents dans la
        fenêtre temporelle pour la même valeur de group_by, sans ordre.

        Args:
            rule: Règle YAML avec champ 'condition'.
            event: Événement courant normalisé.

        Returns:
            Dict alerte si tous les types coexistent, None sinon.
        """
        condition  = rule["condition"]
        req_types  = condition["event_types"]
        window_s   = condition["window_seconds"]
        group_by   = condition["group_by"]
        min_count  = condition.get("min_count_per_type", 1)

        # L'événement courant doit faire partie des types requis
        if event.get("event_type") not in req_types:
            return None

        group_value = event.get(group_by)
        if group_value is None:
            return None

        # Vérifier que chaque type requis a au moins min_count occurrences
        for req_type in req_types:
            count = self.state.count_events(req_type, group_value, group_by, window_s)
            if count < min_count:
                return None

        # Collecter tous les événements des types requis pour l'alerte
        all_events: list[dict] = []
        for req_type in req_types:
            evts = self.state.get_events(req_type, group_value, group_by, window_s, limit=5)
            all_events.extend(evts)

        all_events.sort(key=lambda e: e.get("timestamp", 0))

        return build_alert(
            rule=rule,
            events=all_events,
            attacker_ip=event.get("actor_ip"),
            target_host=event.get("source_host", ""),
            target_ip="",
            yara_match=None,
        )

    def _eval_type4(self, rule: dict, event: dict) -> dict | None:
        """Évalue une règle Type 4 : détection YARA directe.

        Déclenche immédiatement sur samba_write + yara_match présent,
        sans condition préalable ni contexte persisté.

        Args:
            rule: Règle YAML avec champ 'yara_trigger'.
            event: Événement courant normalisé.

        Returns:
            Dict alerte si match YARA, None sinon.
        """
        yara_trigger = rule.get("yara_trigger", {})
        req_type     = yara_trigger.get("event_type", "samba_write")
        req_pattern  = yara_trigger.get("source_host_pattern", "*")

        if event.get("event_type") != req_type:
            return None
        if not fnmatch.fnmatch(event.get("source_host", ""), req_pattern):
            return None

        yara_match = event.get("yara_match")
        if yara_match is None:
            return None

        return build_alert(
            rule=rule,
            events=[event],
            attacker_ip=event.get("actor_ip"),
            target_host=event.get("source_host", ""),
            target_ip="",
            yara_match=yara_match,
        )

    # ------------------------------------------------------------------
    # Chargement des règles
    # ------------------------------------------------------------------

    def _load_rules(self, rules_dir: str) -> None:
        """Charge et valide tous les fichiers YAML du répertoire de règles.

        Les règles invalides sont loggées et ignorées — le moteur continue.

        Args:
            rules_dir: Chemin vers le répertoire contenant les .yaml de règles.
        """
        rules_path = Path(rules_dir)
        if not rules_path.exists():
            logger.warning("Répertoire de règles introuvable : %s", rules_dir)
            return

        yaml_files = list(rules_path.glob("*.yaml")) + list(rules_path.glob("*.yml"))
        if not yaml_files:
            logger.warning("Aucune règle YAML trouvée dans %s", rules_dir)
            return

        for yaml_file in sorted(yaml_files):
            try:
                with open(yaml_file, encoding="utf-8") as f:
                    rule = yaml.safe_load(f)

                if not isinstance(rule, dict):
                    logger.error("Règle invalide (non-dict) : %s", yaml_file)
                    continue

                # Validation optionnelle contre le JSON Schema
                if self._schema:
                    try:
                        jsonschema.validate(instance=rule, schema=self._schema)
                    except jsonschema.ValidationError as exc:
                        logger.error("Règle %s invalide (schéma) : %s", yaml_file.name, exc.message)
                        continue

                self.rules.append(rule)
                logger.info("Règle chargée : %s (type %s)", rule.get("rule_id"), rule.get("type"))

            except yaml.YAMLError as exc:
                logger.error("Erreur YAML dans %s : %s", yaml_file, exc)
            except OSError as exc:
                logger.error("Impossible de lire %s : %s", yaml_file, exc)

        logger.info("RuleEngine : %d règle(s) chargée(s)", len(self.rules))

    @staticmethod
    def _load_rule_schema() -> dict | None:
        """Charge le JSON Schema de validation des règles.

        Returns:
            Dict du schéma ou None si le fichier est inaccessible.
        """
        if _RULE_SCHEMA_PATH.exists():
            try:
                with open(_RULE_SCHEMA_PATH, encoding="utf-8") as f:
                    return json.load(f)
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Impossible de charger rule-schema.json : %s", exc)
        return None

    @staticmethod
    def _slim_event(event: dict) -> dict:
        """Extrait les champs essentiels d'un événement pour stockage en contexte.

        Args:
            event: Événement normalisé complet.

        Returns:
            Dict réduit aux champs utiles pour la corrélation et l'alerte.
        """
        return {
            "timestamp":   event.get("timestamp"),
            "event_type":  event.get("event_type"),
            "source_host": event.get("source_host"),
            "actor_ip":    event.get("actor_ip"),
            "actor_user":  event.get("actor_user"),
            "yara_match":  event.get("yara_match"),
            "raw_log":     event.get("raw_log", ""),
        }

    @staticmethod
    def _check_extra_filter(event: dict, filters: dict) -> bool:
        """Vérifie les filtres optionnels sur le champ extra de l'événement.

        Actuellement supporte le filtre http_status pour WEB_BRUTEFORCE.

        Args:
            event: Événement normalisé.
            filters: Dict de filtres (ex: {'http_status': [401, 403]}).

        Returns:
            True si tous les filtres sont satisfaits, False sinon.
        """
        extra = event.get("extra") or {}
        if "http_status" in filters:
            status = extra.get("http_status")
            if status not in filters["http_status"]:
                return False
        return True