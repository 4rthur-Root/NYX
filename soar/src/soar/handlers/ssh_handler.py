from __future__ import annotations

import logging

from soar.handlers.base_handler import BaseHandler
from soar.handlers.core import handle_block_ip
from soar.models.alert import Alert
from soar.models.decision import Decision
from soar.models.response import Response

logger = logging.getLogger("soar.handlers.ssh")


class SshHandler(BaseHandler):
    def can_handle(self, scenario_type: str) -> bool:
        return scenario_type == "S1"

    def execute(self, alert: Alert, decision: Decision) -> Response:
        logger.info(
            "S1 — SSH brute-force détecté: rule=%s ip=%s target=%s",
            alert.rule_id,
            alert.attacker_ip,
            alert.target_host,
        )
        return handle_block_ip(alert, decision)
