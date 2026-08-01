"""
soar_engine.py — SOAR automation: multi-channel alerting and SIEM forwarding.

Channels: Email (smtplib), Slack, Discord, Telegram, generic webhook, Syslog.
SIEMs: ECS/HTTPS, Splunk HEC, Wazuh TCP, OpenSearch Bulk.

Requirements: 9.6, 9.7, 15.1-15.7
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import smtplib
import socket
import time
from datetime import datetime, timezone
from email.mime.text import MIMEText
from typing import Callable, Optional

import requests

logger = logging.getLogger("netguard.soar_engine")

SEVERITY_ORDER: dict[str, int] = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SOAREngine:
    """Security Orchestration, Automation and Response engine."""

    def __init__(self, settings_repo, log_engine, socketio_emit, geoip_engine=None) -> None:
        self._settings = settings_repo
        self._log_engine = log_engine
        self._emit = socketio_emit or (lambda *a, **kw: None)
        self._geoip = geoip_engine

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def trigger(self, event: dict, enrichment: dict | None = None) -> None:
        """Dispatch notifications to all enabled channels for this event."""
        enrichment = enrichment or {}
        severity = event.get("severity", "Low")
        channels = self._enabled_channels()
        for channel, config in channels.items():
            threshold = config.get("min_severity", "Low")
            if not self._severity_passes(severity, threshold):
                continue
            self._dispatch_with_retry(channel, config, event, enrichment)

    def test_integration(self, channel: str) -> dict:
        """Send a synthetic test event to *channel* and return target's response (Req 15.7)."""
        synthetic = {
            "event_id": "test-0000",
            "attack_type": "Test Event",
            "source_ip": "1.2.3.4",
            "severity": "Low",
            "confidence": 100,
            "timestamp": _utc_now(),
            "rule_name": "TEST",
        }
        config = self._channel_config(channel)
        if not config:
            return {"success": False, "error": "Channel not configured"}

        try:
            result = self._send_to_channel(channel, config, synthetic, {})
            return {"success": True, "channel": channel, "result": result}
        except Exception as exc:
            return {"success": False, "channel": channel, "error": str(exc)}

    # ------------------------------------------------------------------
    # Severity gating (pure function — tested by Property 14)
    # ------------------------------------------------------------------

    @staticmethod
    def _severity_passes(event_severity: str, threshold: str) -> bool:
        return SEVERITY_ORDER.get(event_severity, 0) >= SEVERITY_ORDER.get(threshold, 0)

    # ------------------------------------------------------------------
    # Retry loop
    # ------------------------------------------------------------------

    def _dispatch_with_retry(self, channel: str, config: dict, event: dict, enrichment: dict) -> None:
        delays = [2, 4, 8]
        for attempt, delay in enumerate(delays):
            try:
                self._send_to_channel(channel, config, event, enrichment)
                return
            except Exception as exc:
                logger.warning("SOAREngine: %s attempt %d failed: %s", channel, attempt + 1, exc)
                if attempt < len(delays) - 1:
                    time.sleep(delay)

        # All retries exhausted (Req 15.5)
        logger.error("SOAREngine: channel %s degraded after 3 retries", channel)
        if self._settings:
            self._settings.set(f"soar.{channel}.status", "degraded")
        self._emit("channel_degraded", {"channel": channel})

    # ------------------------------------------------------------------
    # Channel dispatchers
    # ------------------------------------------------------------------

    def _send_to_channel(self, channel: str, config: dict, event: dict, enrichment: dict) -> dict:
        body = self._format_notification(event, enrichment)
        if channel == "slack":
            return self._send_slack(config, body)
        elif channel == "discord":
            return self._send_discord(config, body)
        elif channel == "telegram":
            return self._send_telegram(config, body)
        elif channel == "webhook":
            return self._send_webhook(config, body)
        elif channel == "email":
            return self._send_email(config, body)
        elif channel == "syslog":
            return self._send_syslog(config, body)
        else:
            raise ValueError(f"Unknown channel: {channel}")

    def _send_slack(self, config: dict, body: str) -> dict:
        resp = requests.post(config["webhook_url"], json={"text": body}, timeout=10)
        resp.raise_for_status()
        return {"status": resp.status_code}

    def _send_discord(self, config: dict, body: str) -> dict:
        resp = requests.post(config["webhook_url"], json={"content": body}, timeout=10)
        resp.raise_for_status()
        return {"status": resp.status_code}

    def _send_telegram(self, config: dict, body: str) -> dict:
        bot_token = config["bot_token"]
        chat_id = config["chat_id"]
        resp = requests.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json={"chat_id": chat_id, "text": body},
            timeout=10,
        )
        resp.raise_for_status()
        return {"status": resp.status_code}

    def _send_webhook(self, config: dict, body: str) -> dict:
        resp = requests.post(config["url"], json={"message": body}, timeout=10)
        resp.raise_for_status()
        return {"status": resp.status_code}

    def _send_email(self, config: dict, body: str) -> dict:
        msg = MIMEText(body)
        msg["Subject"] = f"[NetGuard] Security Alert"
        msg["From"] = config.get("from", "netguard@localhost")
        msg["To"] = config["to"]
        with smtplib.SMTP(config.get("host", "localhost"), int(config.get("port", 587))) as s:
            if config.get("starttls", True):
                s.starttls()
            if config.get("username"):
                s.login(config["username"], config.get("password", ""))
            s.send_message(msg)
        return {"status": "sent"}

    def _send_syslog(self, config: dict, body: str) -> dict:
        host = config.get("host", "localhost")
        port = int(config.get("port", 514))
        proto = config.get("protocol", "udp")
        if proto == "tcp":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((host, port))
                s.sendall((body + "\n").encode())
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(body.encode(), (host, port))
        return {"status": "sent"}

    # ------------------------------------------------------------------
    # SIEM forwarding
    # ------------------------------------------------------------------

    def forward_to_siem(self, event: dict) -> None:
        """Forward to all enabled SIEM integrations."""
        if self._is_enabled("siem.elastic"):
            self._forward_elastic(event)
        if self._is_enabled("siem.splunk"):
            self._forward_splunk(event)
        if self._is_enabled("siem.wazuh"):
            self._forward_wazuh(event)
        if self._is_enabled("siem.opensearch"):
            self._forward_opensearch(event)

    def _forward_elastic(self, event: dict) -> None:
        url = self._get("siem.elastic_url")
        if not url:
            return
        resp = requests.post(url, json=event, timeout=10)
        resp.raise_for_status()

    def _forward_splunk(self, event: dict) -> None:
        url = self._get("siem.splunk_hec_url")
        token = self._get("siem.splunk_token")
        if not url or not token:
            return
        resp = requests.post(url, json={"event": event}, headers={"Authorization": f"Splunk {token}"}, timeout=10)
        resp.raise_for_status()

    def _forward_wazuh(self, event: dict) -> None:
        host = self._get("siem.wazuh_host")
        port = int(self._get("siem.wazuh_port") or 514)
        if not host:
            return
        payload = json.dumps(event).encode()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((host, port))
            s.sendall(payload + b"\n")

    def _forward_opensearch(self, event: dict) -> None:
        url = self._get("siem.opensearch_url")
        if not url:
            return
        resp = requests.post(url, json=event, timeout=10)
        resp.raise_for_status()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _format_notification(self, event: dict, enrichment: dict) -> str:
        geo = {}
        if self._geoip:
            from backend.services.geoip_engine import GeoIPError
            resolved = self._geoip.resolve(event.get("source_ip", ""))
            if not isinstance(resolved, GeoIPError):
                geo = resolved
        country = geo.get("country", "Unknown")
        return (
            f"[NetGuard Alert] {event.get('attack_type', 'Unknown Attack')}\n"
            f"Source: {event.get('source_ip', '?')} ({country})\n"
            f"Severity: {event.get('severity', '?')} | Confidence: {event.get('confidence', '?')}%\n"
            f"Time: {event.get('timestamp', _utc_now())}\n"
            f"Rule: {event.get('rule_name', '?')}"
        )

    def _enabled_channels(self) -> dict[str, dict]:
        channels = {}
        for ch in ("slack", "discord", "telegram", "webhook", "email", "syslog"):
            if self._is_enabled(f"soar.{ch}.enabled"):
                cfg = self._channel_config(ch)
                if cfg:
                    channels[ch] = cfg
        return channels

    def _channel_config(self, channel: str) -> Optional[dict]:
        try:
            raw = self._get(f"soar.{channel}.config")
            if raw:
                return json.loads(raw)
        except Exception:
            pass
        return None

    def _is_enabled(self, key: str) -> bool:
        val = self._get(key)
        return val in ("true", "1", "yes", True)

    def _get(self, key: str) -> Optional[str]:
        if self._settings:
            return self._settings.get(key)
        return None
