# state_manager.py
import json
import logging
import sqlite3
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)


class StateManager:
    """Interface unique avec SQLite pour la persistance des événements et contextes.

    Utilise SQLite en mode WAL pour permettre des lectures concurrentes.
    Un Lock threading protège les écritures uniquement.

    Attributes:
        db_path: Chemin vers le fichier SQLite ou ':memory:' pour les tests.
    """

    def __init__(self, db_path: str) -> None:
        """Initialise la connexion SQLite et crée les tables si nécessaire.

        Args:
            db_path: Chemin absolu vers engine.db, ou ':memory:' pour les tests.
        """
        self.db_path = db_path
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        """Configure SQLite WAL et crée les tables avec index. Idempotent."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute("PRAGMA synchronous=NORMAL;")
            cur.execute("PRAGMA busy_timeout=5000;")
            cur.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   INTEGER NOT NULL,
                    source_host TEXT    NOT NULL,
                    event_type  TEXT    NOT NULL,
                    actor_ip    TEXT,
                    actor_user  TEXT,
                    target_host TEXT,
                    target_port INTEGER,
                    extra       TEXT,
                    yara_match  TEXT,
                    raw_log     TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_ts
                    ON events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_type_ip
                    ON events(event_type, actor_ip);
                CREATE INDEX IF NOT EXISTS idx_events_type_user
                    ON events(event_type, actor_user);

                CREATE TABLE IF NOT EXISTS contexts (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id    TEXT    NOT NULL,
                    actor_ip   TEXT,
                    actor_user TEXT,
                    state      TEXT    NOT NULL DEFAULT 'pending',
                    step       INTEGER DEFAULT 0,
                    first_seen INTEGER NOT NULL,
                    last_seen  INTEGER NOT NULL,
                    extra      TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_contexts_rule_ip
                    ON contexts(rule_id, actor_ip);
                CREATE INDEX IF NOT EXISTS idx_contexts_rule_user
                    ON contexts(rule_id, actor_user);
            """)
            self.conn.commit()

    # --- Écritures (Lock) ---

    def store_event(self, event: dict) -> int:
        """Persiste un événement normalisé.

        Args:
            event: Dict conforme au schéma EventNormalized.

        Returns:
            ID de la ligne insérée.
        """
        with self._lock:
            cur = self.conn.execute(
                """INSERT INTO events
                   (timestamp, source_host, event_type, actor_ip, actor_user,
                    target_host, target_port, extra, yara_match, raw_log)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event["timestamp"],
                    event["source_host"],
                    event["event_type"],
                    event.get("actor_ip"),
                    event.get("actor_user"),
                    event.get("target_host"),
                    event.get("target_port"),
                    json.dumps(event["extra"]) if event.get("extra") is not None else None,
                    json.dumps(event["yara_match"]) if event.get("yara_match") is not None else None,
                    event["raw_log"],
                ),
            )
            self.conn.commit()
            return cur.lastrowid  # type: ignore[return-value]

    def set_context(
        self,
        rule_id: str,
        actor_ip: str | None,
        actor_user: str | None,
        step: int,
        extra: dict | None = None,
        state: str = "pending",
    ) -> None:
        """Crée ou met à jour un contexte de règle séquentielle (Type 2).

        Args:
            rule_id: Identifiant de la règle YAML.
            actor_ip: IP de l'acteur (None si corrélation par user).
            actor_user: Nom d'utilisateur (None si corrélation par IP).
            step: Numéro de l'étape courante.
            extra: Données accumulées (sérialisées JSON).
            state: 'pending', 'escalated' ou 'expired'.
        """
        now_ms = int(time.time() * 1000)
        with self._lock:
            existing = self.conn.execute(
                "SELECT id FROM contexts WHERE rule_id=? AND actor_ip IS ? AND actor_user IS ?",
                (rule_id, actor_ip, actor_user),
            ).fetchone()
            if existing:
                self.conn.execute(
                    "UPDATE contexts SET state=?, step=?, last_seen=?, extra=? WHERE id=?",
                    (state, step, now_ms, json.dumps(extra) if extra is not None else None,
                     existing["id"]),
                )
            else:
                self.conn.execute(
                    """INSERT INTO contexts
                       (rule_id, actor_ip, actor_user, state, step, first_seen, last_seen, extra)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (rule_id, actor_ip, actor_user, state, step, now_ms, now_ms,
                     json.dumps(extra) if extra is not None else None),
                )
            self.conn.commit()

    def delete_context(self, rule_id: str, actor_ip: str | None, actor_user: str | None) -> None:
        """Supprime un contexte après déclenchement ou expiration.

        Args:
            rule_id: Identifiant de la règle.
            actor_ip: IP de l'acteur.
            actor_user: Nom d'utilisateur.
        """
        with self._lock:
            self.conn.execute(
                "DELETE FROM contexts WHERE rule_id=? AND actor_ip IS ? AND actor_user IS ?",
                (rule_id, actor_ip, actor_user),
            )
            self.conn.commit()

    # --- Lectures (pas de Lock, WAL garantit la cohérence) ---

    def count_events(
        self,
        event_type: str,
        group_by_value: str | None,
        group_by_field: str,
        window_s: int,
    ) -> int:
        """Compte les événements d'un type dans une fenêtre temporelle.

        Args:
            event_type: Type d'événement (ex: 'ssh_failure').
            group_by_value: Valeur du champ de groupement.
            group_by_field: 'actor_ip' ou 'actor_user'.
            window_s: Fenêtre en secondes depuis maintenant.

        Returns:
            Nombre d'occurrences.
        """
        since_ms = int((time.time() - window_s) * 1000)
        field = "actor_ip" if group_by_field == "actor_ip" else "actor_user"
        row = self.conn.execute(
            f"SELECT COUNT(*) FROM events WHERE event_type=? AND {field} IS ? AND timestamp >= ?",
            (event_type, group_by_value, since_ms),
        ).fetchone()
        return row[0] if row else 0

    def get_events(
        self,
        event_type: str,
        group_by_value: str | None,
        group_by_field: str,
        window_s: int,
        limit: int = 20,
    ) -> list[dict]:
        """Récupère les événements d'un type dans une fenêtre temporelle.

        Args:
            event_type: Type d'événement.
            group_by_value: Valeur du champ de groupement.
            group_by_field: 'actor_ip' ou 'actor_user'.
            window_s: Fenêtre en secondes depuis maintenant.
            limit: Nombre max de lignes retournées.

        Returns:
            Liste de dicts normalisés.
        """
        since_ms = int((time.time() - window_s) * 1000)
        field = "actor_ip" if group_by_field == "actor_ip" else "actor_user"
        rows = self.conn.execute(
            f"SELECT * FROM events WHERE event_type=? AND {field} IS ? AND timestamp >= ? "
            f"ORDER BY timestamp DESC LIMIT ?",
            (event_type, group_by_value, since_ms, limit),
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_context(
        self, rule_id: str, actor_ip: str | None, actor_user: str | None
    ) -> dict | None:
        """Récupère le contexte d'une règle pour un acteur donné.

        Args:
            rule_id: Identifiant de la règle.
            actor_ip: IP de l'acteur.
            actor_user: Nom d'utilisateur.

        Returns:
            Dict contexte ou None si inexistant.
        """
        row = self.conn.execute(
            "SELECT * FROM contexts WHERE rule_id=? AND actor_ip IS ? AND actor_user IS ?",
            (rule_id, actor_ip, actor_user),
        ).fetchone()
        if row is None:
            return None
        ctx = dict(row)
        if ctx.get("extra"):
            try:
                ctx["extra"] = json.loads(ctx["extra"])
            except (json.JSONDecodeError, TypeError):
                ctx["extra"] = None
        return ctx

    # --- Maintenance (thread purge horaire) ---

    def purge_old_events(self, older_than_s: int = 86400) -> int:
        """Supprime les événements plus anciens que la rétention configurée.

        Args:
            older_than_s: Âge maximum en secondes (défaut 24h).

        Returns:
            Nombre de lignes supprimées.
        """
        cutoff_ms = int((time.time() - older_than_s) * 1000)
        with self._lock:
            cur = self.conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff_ms,))
            self.conn.commit()
        deleted = cur.rowcount
        if deleted:
            logger.info("Purge : %d événements supprimés", deleted)
        return deleted

    def expire_contexts(self, max_age_s: int = 86400) -> int:
        """Expire et supprime les contextes trop anciens.

        Args:
            max_age_s: Âge max en secondes depuis last_seen.

        Returns:
            Nombre de contextes supprimés.
        """
        cutoff_ms = int((time.time() - max_age_s) * 1000)
        with self._lock:
            cur = self.conn.execute(
                "DELETE FROM contexts WHERE last_seen < ? AND state != 'escalated'",
                (cutoff_ms,),
            )
            self.conn.commit()
        deleted = cur.rowcount
        if deleted:
            logger.info("Expire : %d contextes supprimés", deleted)
        return deleted

    def close(self) -> None:
        """Ferme la connexion SQLite proprement."""
        self.conn.close()

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        """Convertit une Row SQLite en dict avec désérialisation JSON.

        Args:
            row: Ligne SQLite (row_factory=sqlite3.Row requis).

        Returns:
            Dict Python avec extra et yara_match désérialisés.
        """
        d = dict(row)
        for field in ("extra", "yara_match"):
            if d.get(field):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    d[field] = None
        return d
