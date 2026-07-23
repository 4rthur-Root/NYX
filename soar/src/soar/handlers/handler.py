from __future__ import annotations

import logging
import time
from typing import Callable, Optional

from soar.integrations import OPNsenseClient
from soar.models.alert import Alert
from soar.models.decision import Decision
from soar.models.response import OpnsenseResult, Response

logger = logging.getLogger("soar.handlers")

HandlerFn = Callable[[Alert, Decision], Response]


def _base_response(alert: Alert, decision: Decision) -> dict:
    now_ms = int(time.time() * 1000)
    return {
        "response_id": f"resp-{alert.alert_id}",
        "alert_id": alert.alert_id,
        "alert_timestamp": alert.timestamp,
        "response_timestamp": now_ms,
        "latency_ms": now_ms - alert.timestamp,
        "action": decision.action,
        "skip_reason": decision.skip_reason,
        "enrichment": decision.enrichment,
    }


def handle_block_ip(alert: Alert, decision: Decision) -> Response:
    client = OPNsenseClient()
    ip = alert.attacker_ip

    if not ip:
        return Response(
            **_base_response(alert, decision),
            status="error",
            error="attacker_ip is None, cannot block",
        )

    opnsense = client.block_ip(ip)
    status = "success" if opnsense.api_status_code == 200 else "error"

    return Response(
        **_base_response(alert, decision),
        status=status,
        opnsense=opnsense,
    )


def handle_notify(alert: Alert, decision: Decision) -> Response:
    logger.info(
        "NOTIFY — rule=%s scenario=%s ip=%s enrichment=%s",
        alert.rule_id,
        decision.scenario_type,
        alert.attacker_ip,
        decision.enrichment,
    )

    return Response(
        **_base_response(alert, decision),
        status="success",
    )


def handle_ignore(alert: Alert, decision: Decision) -> Response:
    return Response(
        **_base_response(alert, decision),
        status="skipped",
    )


HANDLERS: dict[str, HandlerFn] = {
    "block_ip": handle_block_ip,
    "notify": handle_notify,
    "none": handle_ignore,
}
