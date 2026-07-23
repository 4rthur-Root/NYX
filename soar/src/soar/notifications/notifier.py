from __future__ import annotations

import logging
import smtplib
import time
from email.mime.text import MIMEText
from typing import Optional

import requests

from soar.config.settings import settings
from soar.models.response import Response
from soar.repositories import ResponseRepository

logger = logging.getLogger("soar.notifications")


class Notifier:
    def __init__(self):
        self._repo = ResponseRepository()

    def send_immediate_alert(self, response: Response):
        if not self._should_notify(response):
            return

        subject = f"[SOAR] Alerte {response.action} — {response.alert_id}"
        body = self._format_response(response)

        self._try_telegram(subject, body)
        self._try_smtp(subject, body)

    def send_daily_summary(self):
        cutoff = int(time.time() * 1000) - 86400000
        recent = self._repo.list_recent(limit=100)
        recent = [r for r in recent if r.response_timestamp >= cutoff]

        if not recent:
            logger.info("Aucune activité SOAR dans les dernières 24h")
            return

        success = sum(1 for r in recent if r.status == "success")
        failed = sum(1 for r in recent if r.status == "error")
        skipped = sum(1 for r in recent if r.status == "skipped")

        lines = [
            "=== Résumé quotidien SOAR ===",
            f"Période: dernières 24h",
            f"Total réponses: {len(recent)}",
            f"  ✅ Succès: {success}",
            f"  ❌ Échecs: {failed}",
            f"  ⏭ Ignorées: {skipped}",
            "",
        ]
        for r in recent[:10]:
            lines.append(
                f"  [{r.status}] {r.alert_id} → {r.action} "
                f"({r.latency_ms}ms)"
            )
        if len(recent) > 10:
            lines.append(f"  ... et {len(recent) - 10} autres")

        body = "\n".join(lines)
        self._try_telegram("SOAR — Résumé quotidien", body)
        self._try_smtp("SOAR — Résumé quotidien", body)

    def _should_notify(self, response: Response) -> bool:
        if response.status == "error":
            return True
        if response.enrichment and response.enrichment.abuseipdb_score is not None:
            if response.enrichment.abuseipdb_score > 95:
                return True
        return False

    def _format_response(self, response: Response) -> str:
        lines = [
            f"Alerte: {response.alert_id}",
            f"Action: {response.action}",
            f"Statut: {response.status}",
            f"Latence: {response.latency_ms}ms",
        ]
        if response.skip_reason:
            lines.append(f"Raison: {response.skip_reason}")
        if response.error:
            lines.append(f"Erreur: {response.error}")
        if response.enrichment:
            lines.append(f"Score AbuseIPDB: {response.enrichment.abuseipdb_score}")
        if response.opnsense:
            lines.append(f"OPNsense: HTTP {response.opnsense.api_status_code}")
        return "\n".join(lines)

    def _try_telegram(self, subject: str, body: str):
        token = settings.telegram_bot_token
        chat_id = settings.telegram_chat_id
        if not token or not chat_id:
            logger.debug("Telegram non configuré, notification ignorée")
            return

        try:
            text = f"*{subject}*\n\n{body}"
            resp = requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
                timeout=10,
            )
            if resp.status_code != 200:
                logger.warning("Telegram API error: %s", resp.text[:200])
        except requests.RequestException as e:
            logger.warning("Telegram indisponible: %s", e)

    def _try_smtp(self, subject: str, body: str):
        host = settings.smtp_host
        if not host:
            logger.debug("SMTP non configuré, notification ignorée")
            return

        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = settings.smtp_user or "soar@nyx.local"
        msg["To"] = settings.smtp_to or ""

        try:
            with smtplib.SMTP(host, settings.smtp_port, timeout=10) as s:
                if settings.smtp_user and settings.smtp_password:
                    s.starttls()
                    s.login(settings.smtp_user, settings.smtp_password)
                s.send_message(msg)
        except Exception as e:
            logger.warning("SMTP indisponible: %s", e)
