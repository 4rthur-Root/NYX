from __future__ import annotations

import logging

from soar.handlers.base_handler import BaseHandler
from soar.handlers.core import handle_block_ip, handle_notify
from soar.models.alert import Alert
from soar.models.decision import Decision
from soar.models.response import Response

logger = logging.getLogger("soar.handlers.smb")


class SmbHandler(BaseHandler):
    def can_handle(self, scenario_type: str) -> bool:
        return scenario_type == "S2"

    def execute(self, alert: Alert, decision: Decision) -> Response:
        logger.info(
            "S2 — Exfiltration SMB détectée: rule=%s ip=%s target=%s",
            alert.rule_id,
            alert.attacker_ip,
            alert.target_host,
        )
        return handle_block_ip(alert, decision)
