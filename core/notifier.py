"""Argus V2 - Notification Engine (Discord / Slack)"""

import json
import urllib.request
import urllib.error
from typing import Optional, List
from core.models import Finding, Severity
from core.logger import get_logger

log = get_logger('notifier')

SEVERITY_COLOR = {
    Severity.CRITICAL: 0xFF0000,  # Red
    Severity.HIGH:     0xFF8C00,  # Orange
    Severity.MEDIUM:   0xFFD700,  # Yellow
    Severity.LOW:      0x00BFFF,  # Blue
    Severity.INFO:     0xAAAAAA,  # Gray
}

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
    Severity.INFO:     "⚪",
}


def _http_post(url: str, data: dict) -> bool:
    try:
        payload = json.dumps(data).encode('utf-8')
        req = urllib.request.Request(url, data=payload,
                                     headers={'Content-Type': 'application/json'})
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception as e:
        log.error(f"Notification failed: {e}")
        return False


def send_discord(webhook_url: str, finding: Finding, domain: str) -> bool:
    """Send a finding embed to Discord."""
    emoji = SEVERITY_EMOJI.get(finding.severity, "•")
    color = SEVERITY_COLOR.get(finding.severity, 0xAAAAAA)

    embed = {
        "title":       f"{emoji} {finding.title}",
        "color":       color,
        "description": finding.evidence[:1024] if finding.evidence else "—",
        "fields": [
            {"name": "Domain",   "value": domain,                    "inline": True},
            {"name": "Severity", "value": finding.severity.value.upper(), "inline": True},
            {"name": "Module",   "value": finding.module_source or "—",   "inline": True},
            {"name": "URL",      "value": finding.url or "—",             "inline": False},
        ],
        "footer": {"text": f"Argus V2 | {finding.timestamp[:19]}"},
    }
    return _http_post(webhook_url, {"embeds": [embed]})


def send_slack(webhook_url: str, finding: Finding, domain: str) -> bool:
    """Send a finding to Slack via incoming webhook."""
    emoji = SEVERITY_EMOJI.get(finding.severity, "•")
    text  = (
        f"{emoji} *{finding.severity.value.upper()}* — {finding.title}\n"
        f"Domain: `{domain}` | Module: `{finding.module_source or '?'}`\n"
        f"URL: {finding.url or '—'}\n"
        f"Evidence: `{(finding.evidence or '')[:300]}`"
    )
    return _http_post(webhook_url, {"text": text})


class Notifier:
    def __init__(self, discord_webhook: str = "", slack_webhook: str = "",
                 notify_severities: Optional[List[str]] = None):
        self.discord_webhook = discord_webhook
        self.slack_webhook   = slack_webhook
        self.notify_severities = set(notify_severities or ['critical', 'high'])

    def should_notify(self, finding: Finding) -> bool:
        return finding.severity.value in self.notify_severities

    def notify(self, finding: Finding, domain: str) -> None:
        if not self.should_notify(finding):
            return
        if self.discord_webhook:
            send_discord(self.discord_webhook, finding, domain)
        if self.slack_webhook:
            send_slack(self.slack_webhook, finding, domain)

    def notify_new_subdomain(self, subdomain: str, domain: str) -> None:
        """Quick notification for newly discovered subdomain."""
        if 'new_subdomain' not in self.notify_severities:
            return
        msg = f"🆕 New subdomain discovered: `{subdomain}` (domain: {domain})"
        if self.discord_webhook:
            _http_post(self.discord_webhook, {"content": msg})
        if self.slack_webhook:
            _http_post(self.slack_webhook, {"text": msg})
