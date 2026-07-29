"""Utilitaires temporels partagés par les simulateurs de bruit de fond.

Applique une notion de "journée de travail" : en dehors de la plage
WORKDAY_START_HOUR - WORKDAY_END_HOUR, l'activité ralentit fortement
plutôt que de s'arrêter net (certains outils automatiques/sauvegardes
tournent la nuit, mais un employé n'est pas censé naviguer sur l'ERP
à 3h du matin — Topologie.pdf §2, principe de fidélité contextuelle).
"""

import datetime
import random
import time

from traffic.config import (
    OFF_HOURS_JITTER_MULTIPLIER,
    WORKDAY_END_HOUR,
    WORKDAY_START_HOUR,
)


def is_workday_hours(now: datetime.datetime | None = None) -> bool:
    now = now or datetime.datetime.now()
    return WORKDAY_START_HOUR <= now.hour < WORKDAY_END_HOUR


def sleep_with_workday_jitter(jitter_range: tuple[float, float], stop_event=None) -> None:
    """Dort pendant une durée aléatoire dans jitter_range, multipliée si on
    est hors des heures de bureau. Vérifie stop_event périodiquement pour
    permettre un arrêt réactif même pendant une longue pause."""
    base = random.uniform(*jitter_range)
    if not is_workday_hours():
        base *= OFF_HOURS_JITTER_MULTIPLIER

    elapsed = 0.0
    step = 1.0
    while elapsed < base:
        if stop_event is not None and stop_event.is_set():
            return
        to_sleep = min(step, base - elapsed)
        time.sleep(to_sleep)
        elapsed += to_sleep