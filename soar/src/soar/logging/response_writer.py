from __future__ import annotations

import logging

from soar.models.response import Response
from soar.repositories import ResponseRepository

logger = logging.getLogger("soar.logging.response_writer")


class ResponseWriter:
    def __init__(self):
        self._repo = ResponseRepository()

    def write(self, response: Response):
        self._repo.save(response)
        logger.debug(
            "Réponse persistée: alert=%s action=%s status=%s",
            response.alert_id,
            response.action,
            response.status,
        )
