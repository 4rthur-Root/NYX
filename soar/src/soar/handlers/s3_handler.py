from __future__ import annotations

import logging
import time
from typing import Optional

from soar.handlers.base_handler import BaseHandler
from soar.handlers.core import handle_block_ip, handle_notify
from soar.models.alert import Alert
from soar.models.decision import Decision
from soar.models.response import Response

logger = logging.getLogger("soar.handlers.s3")


class S3Handler(BaseHandler):
    def can_handle(self, scenario_type: str) -> bool:
        return scenario_type == "S3"

    def execute(self, alert: Alert, decision: Decision) -> Response:
        logger.info(
            "S3 — Fichier malveillant détecté: rule=%s target=%s ip=%s",
            alert.rule_id,
            alert.target_host,
            alert.attacker_ip,
        )

        notify_response = handle_notify(alert, decision)

        if alert.attacker_ip is not None:
            block_response = handle_block_ip(alert, decision)
            return Response(
                response_id=notify_response.response_id,
                alert_id=notify_response.alert_id,
                alert_timestamp=notify_response.alert_timestamp,
                response_timestamp=notify_response.response_timestamp,
                latency_ms=notify_response.latency_ms,
                action="notify",
                status="success" if notify_response.status == "success" and block_response.status == "success" else "error",
                skip_reason=notify_response.skip_reason,
                enrichment=notify_response.enrichment,
                opnsense=block_response.opnsense,
                error=block_response.error or notify_response.error,
            )

        return notify_response
