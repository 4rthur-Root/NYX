#!/usr/bin/env python3
"""Clean up expired OPNsense block rules based on SOAR rule_ttl_hours."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from soar.config.settings import settings
from soar.db.connection import get_connection
from soar.integrations import OPNsenseClient

logger = logging.getLogger("soar.scripts.cleanup")


def _now_ms() -> int:
    import time
    return int(time.time() * 1000)


def find_expired() -> list[tuple[str, str, int]]:
    ttl_ms = settings.rule_ttl_hours * 3600 * 1000
    cutoff = _now_ms() - ttl_ms

    conn = get_connection()
    rows = conn.execute("""
        SELECT o.blocked_ip, o.rule_id, r.response_timestamp
        FROM opnsense_actions o
        JOIN responses r ON r.response_id = o.response_id
        WHERE o.api_status_code = 200
          AND o.blocked_ip IS NOT NULL
          AND r.response_timestamp < ?
    """, (cutoff,)).fetchall()

    return [(row[0], row[1], row[2]) for row in rows]


def unblock(ip: str, rule_id: str) -> bool:
    client = OPNsenseClient()
    result = client.unblock_ip(ip)
    if result.api_status_code == 200:
        logger.info("Unblocked expired IP: %s (rule=%s)", ip, rule_id)
        return True
    logger.warning(
        "Failed to unblock expired IP %s (rule=%s): HTTP %s",
        ip, rule_id, result.api_status_code,
    )
    return False


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    expired = find_expired()
    if not expired:
        logger.info("No expired rules to clean up.")
        return

    logger.info("Found %d expired rule(s).", len(expired))
    success = 0
    failed = 0
    for ip, rule_id, ts in expired:
        if unblock(ip, rule_id):
            success += 1
        else:
            failed += 1

    logger.info("Cleanup complete: %d unblocked, %d failed.", success, failed)
    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
