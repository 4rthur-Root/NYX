from __future__ import annotations

import ipaddress
import logging
from typing import Optional

from soar.config.settings import settings
from soar.engine import rules
from soar.integrations import AbuseIPDBClient
from soar.models.alert import Alert
from soar.models.decision import Decision, EnrichmentResult

logger = logging.getLogger("soar.engine")


class DecisionEngine:
    def __init__(self, abuseipdb: Optional[AbuseIPDBClient] = None):
        self._abuseipdb = abuseipdb or AbuseIPDBClient()

    def decide(self, alert: Alert) -> Decision:
        scenario_type = rules.RULE_TO_SCENARIO.get(alert.rule_id)
        if scenario_type is None:
            logger.warning("rule_id inconnu: %s — skip", alert.rule_id)
            return Decision(
                alert=alert,
                scenario_type="UNKNOWN",
                action="none",
                skip_reason="whitelisted",
            )

        if alert.severity == "WARNING":
            return Decision(
                alert=alert,
                scenario_type=scenario_type,
                action="none",
                skip_reason="severity_warning",
            )

        if alert.attacker_ip is None and scenario_type in rules.SCENARIOS_EXPECTING_IP:
            return Decision(
                alert=alert,
                scenario_type=scenario_type,
                action="none",
                skip_reason="attacker_ip_null",
            )

        if alert.attacker_ip is not None and self._is_whitelisted(alert.attacker_ip):
            return Decision(
                alert=alert,
                scenario_type=scenario_type,
                action="none",
                skip_reason="whitelisted",
            )

        enrichment: Optional[EnrichmentResult] = None
        action_override: Optional[str] = None

        if alert.attacker_ip is not None:
            enrichment = self._abuseipdb.get_reputation(alert.attacker_ip)
            if (
                enrichment.abuseipdb_score is not None
                and enrichment.abuseipdb_score < settings.abuseipdb_score_threshold
            ):
                action_override = "notify"

        action = action_override or rules.PLAYBOOK.get(alert.rule_id, "none")

        return Decision(
            alert=alert,
            scenario_type=scenario_type,
            action=action,
            enrichment=enrichment,
        )

    def _is_whitelisted(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            for cidr in rules.WHITELIST:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
        except ValueError:
            logger.warning("IP invalide pour whitelist: %s", ip)
        return False
