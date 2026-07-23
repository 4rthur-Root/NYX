# main.py
"""Point d'entrée NyxSOC Engine.

Orchestration uniquement — aucune logique métier ici.
Ordre d'instanciation obligatoire (spec engine.md §4.1) :
    StateManager → YaraScanner → RuleEngine(state, yara)
    → Alerter → Validator → Dispatcher(parsers, validator, state, yara, alerter)
    → Reader(dispatcher, config)
"""
import logging
import queue
import signal
import sys
import threading
import time
from pathlib import Path

import yaml

# --- Imports engine ---
from state_manager import StateManager
from yara_scanner import YaraScanner
from rule_engine import RuleEngine
from alerter import Alerter
from validator import EventValidator
from dispatcher import Dispatcher
from reader import Reader

from parsers.syslog_parser import SyslogParser
from parsers.filterlog_parser import FilterlogParser
from parsers.windows_parser import WindowsParser

# ---------------------------------------------------------------------------
# Logging principal (console + fichier)
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("nyxsoc.main")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
_CONFIG_PATH = Path(__file__).parent / "config.yaml"


def load_config(path: Path) -> dict:
    """Charge et valide la configuration engine.

    Args:
        path: Chemin vers config.yaml.

    Returns:
        Dict de configuration.

    Raises:
        SystemExit: Si le fichier est manquant ou invalide.
    """
    if not path.exists():
        logger.critical("config.yaml introuvable : %s", path)
        sys.exit(1)
    try:
        with open(path, encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        logger.critical("Erreur config.yaml : %s", exc)
        sys.exit(1)

    required_keys = ["sources", "retention", "queue", "log_dir", "db_path",
                     "alerts_dir", "alerts_log"]
    for key in required_keys:
        if key not in cfg:
            logger.critical("Clé manquante dans config.yaml : '%s'", key)
            sys.exit(1)
    return cfg


# ---------------------------------------------------------------------------
# Thread consommateur de la queue
# ---------------------------------------------------------------------------

def _consumer_loop(
    shared_queue: queue.Queue,
    dispatcher: Dispatcher,
    stop_event: threading.Event,
) -> None:
    """Thread consommateur — dépile la queue et appelle dispatcher.dispatch().

    Args:
        shared_queue: Queue thread-safe partagée avec le Reader.
        dispatcher: Dispatcher instancié dans main().
        stop_event: Event de signalisation pour l'arrêt propre.
    """
    logger.info("Consommateur queue démarré")
    while not stop_event.is_set():
        try:
            item = shared_queue.get(timeout=1.0)
        except queue.Empty:
            continue

        if item is None:  # sentinel pour arrêt propre
            break

        line, filename = item
        try:
            dispatcher.dispatch(line, filename)
        except Exception as exc:
            logger.error("Erreur Dispatcher non interceptée : %s", exc)
        finally:
            shared_queue.task_done()

    logger.info("Consommateur queue arrêté")


# ---------------------------------------------------------------------------
# Thread de purge horaire
# ---------------------------------------------------------------------------

def _purge_loop(
    state: StateManager,
    retention_s: int,
    context_interval_s: int,
    stop_event: threading.Event,
) -> None:
    """Thread de maintenance — purge SQLite toutes les heures.

    Args:
        state: StateManager partagé.
        retention_s: Durée de rétention des événements en secondes.
        context_interval_s: Intervalle de nettoyage des contextes en secondes.
        stop_event: Event de signalisation pour l'arrêt propre.
    """
    logger.info("Thread purge démarré (rétention=%ds)", retention_s)
    while not stop_event.is_set():
        # Attendre l'intervalle configuré (avec réveil anticipé sur stop_event)
        stop_event.wait(timeout=context_interval_s)
        if stop_event.is_set():
            break
        state.purge_old_events(older_than_s=retention_s)
        state.expire_contexts(max_age_s=retention_s)


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

def main() -> None:
    """Orchestre le démarrage complet du moteur NyxSOC.

    Instancie les composants dans l'ordre strict de la spec,
    lance les threads et attend SIGTERM ou KeyboardInterrupt.
    """
    logger.info("=== NyxSOC Engine — démarrage ===")

    # 1. Configuration
    cfg = load_config(_CONFIG_PATH)

    log_dir     = cfg["log_dir"]
    db_path     = cfg["db_path"]
    alerts_dir  = cfg["alerts_dir"]
    alerts_log  = cfg["alerts_log"]
    queue_max   = cfg["queue"].get("maxsize", 10_000)
    retention_h = cfg["retention"].get("events_hours", 24)
    cleanup_s   = cfg["retention"].get("context_cleanup_interval_seconds", 3600)
    retention_s = retention_h * 3600
    rules_dir   = cfg.get("rules", {}).get("attack", "engine/rules/attack")
    yara_dir    = "engine/rules/yara"
    samba_mounts = cfg.get("samba_mounts", {})
    sources_map  = cfg["sources"]  # {filename: parser_type}

    # 2. Vérifier /var/log/remote/
    if not Path(log_dir).exists():
        logger.warning("log_dir '%s' introuvable — le Reader attendra", log_dir)

    # 3. Instanciation dans l'ordre obligatoire
    logger.info("Init StateManager (%s)", db_path)
    state = StateManager(db_path)

    logger.info("Init YaraScanner (%s)", yara_dir)
    yara = YaraScanner(yara_dir)

    logger.info("Init RuleEngine (%s)", rules_dir)
    rule_engine = RuleEngine(state, yara, rules_dir)

    logger.info("Init Alerter")
    alerter = Alerter(alerts_dir, alerts_log)

    logger.info("Init EventValidator")
    validator = EventValidator()

    # 4. Instancier les parsers selon la config
    parser_map = {
        "syslog":    SyslogParser(),
        "filterlog": FilterlogParser(),
        "windows":   WindowsParser(),
    }
    parsers: dict = {}
    for filename, parser_type in sources_map.items():
        if parser_type in parser_map:
            parsers[filename] = parser_map[parser_type]
        else:
            logger.warning("Type de parser inconnu '%s' pour '%s' — ignoré",
                           parser_type, filename)

    logger.info("Init Dispatcher (%d source(s))", len(parsers))
    shared_queue: queue.Queue = queue.Queue(maxsize=queue_max)
    dispatcher = Dispatcher(
        parsers=parsers,
        validator=validator,
        state=state,
        yara=yara,
        rule_engine=rule_engine,
        alerter=alerter,
        samba_mounts=samba_mounts,
    )

    logger.info("Init Reader (%s)", log_dir)
    reader = Reader(
        log_dir=log_dir,
        sources=set(sources_map.keys()),
        shared_queue=shared_queue,
        maxsize=queue_max,
    )

    # 5. Stop event partagé entre les threads
    stop_event = threading.Event()

    # 6. Gestionnaires de signaux pour l'arrêt propre
    def _signal_handler(signum, frame) -> None:
        logger.info("Signal %d reçu — arrêt en cours...", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    # 7. Lancer les threads
    consumer_thread = threading.Thread(
        target=_consumer_loop,
        args=(shared_queue, dispatcher, stop_event),
        name="consumer",
        daemon=True,
    )
    purge_thread = threading.Thread(
        target=_purge_loop,
        args=(state, retention_s, cleanup_s, stop_event),
        name="purge",
        daemon=True,
    )

    consumer_thread.start()
    purge_thread.start()

    try:
        reader.start()
    except FileNotFoundError as exc:
        logger.critical("Impossible de démarrer le Reader : %s", exc)
        stop_event.set()

    logger.info("=== NyxSOC Engine opérationnel ===")

    # 8. Boucle principale — attendre le signal d'arrêt
    try:
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt — arrêt...")
        stop_event.set()

    # 9. Arrêt propre
    logger.info("Arrêt des composants...")
    reader.stop()

    # Sentinel pour débloquer le consommateur s'il est en attente
    shared_queue.put(None)
    consumer_thread.join(timeout=5)
    purge_thread.join(timeout=2)

    state.close()
    logger.info("=== NyxSOC Engine arrêté proprement ===")


if __name__ == "__main__":
    main()