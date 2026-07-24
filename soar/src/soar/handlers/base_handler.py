from __future__ import annotations

from abc import ABC, abstractmethod

from soar.models.alert import Alert
from soar.models.decision import Decision
from soar.models.response import Response


class BaseHandler(ABC):
    @abstractmethod
    def can_handle(self, scenario_type: str) -> bool:
        ...

    @abstractmethod
    def execute(self, alert: Alert, decision: Decision) -> Response:
        ...
