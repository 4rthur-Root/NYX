from __future__ import annotations

import logging
from typing import Callable, Optional

from soar.handlers.base_handler import BaseHandler
from soar.handlers.core import handle_block_ip, handle_ignore, handle_notify
from soar.handlers.s3_handler import S3Handler
from soar.handlers.smb_handler import SmbHandler
from soar.handlers.ssh_handler import SshHandler
from soar.models.alert import Alert
from soar.models.decision import Decision
from soar.models.response import Response

logger = logging.getLogger("soar.handlers")

HandlerFn = Callable[[Alert, Decision], Response]

HANDLERS: dict[str, HandlerFn] = {
    "block_ip": handle_block_ip,
    "notify": handle_notify,
    "none": handle_ignore,
}

SCENARIO_HANDLERS: list[BaseHandler] = [
    SshHandler(),
    SmbHandler(),
    S3Handler(),
]


def get_handler_for_scenario(scenario_type: str) -> Optional[BaseHandler]:
    for handler in SCENARIO_HANDLERS:
        if handler.can_handle(scenario_type):
            return handler
    return None


def get_handler_for_action(action: str) -> Optional[HandlerFn]:
    return HANDLERS.get(action)


def get_handler(decision: Decision) -> Optional[Callable[[Alert, Decision], Response]]:
    if decision.action == "none":
        return handle_ignore

    if decision.action not in HANDLERS:
        return None

    scenario_handler = get_handler_for_scenario(decision.scenario_type)
    if scenario_handler is not None:
        return scenario_handler.execute

    return HANDLERS[decision.action]
