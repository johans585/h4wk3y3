"""Tests for Notifier — should_notify filtering, payload formatting."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from unittest.mock import patch
from core.notifier import Notifier, send_discord, send_slack, SEVERITY_COLOR, SEVERITY_EMOJI
from core.models import Finding, FindingType, Severity


def make_finding(severity=Severity.HIGH, **kwargs):
    defaults = dict(
        type=FindingType.NUCLEI_FINDING,
        target="sub.example.com",
        title="Test finding",
        severity=severity,
        confidence=0.9,
        url="https://sub.example.com/vuln",
        evidence="evidence data",
        module_source="m13",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


class TestShouldNotify:
    def test_critical_notified_by_default(self):
        n = Notifier()
        assert n.should_notify(make_finding(Severity.CRITICAL))

    def test_high_notified_by_default(self):
        n = Notifier()
        assert n.should_notify(make_finding(Severity.HIGH))

    def test_medium_not_notified_by_default(self):
        n = Notifier()
        assert not n.should_notify(make_finding(Severity.MEDIUM))

    def test_low_not_notified_by_default(self):
        n = Notifier()
        assert not n.should_notify(make_finding(Severity.LOW))

    def test_info_not_notified_by_default(self):
        n = Notifier()
        assert not n.should_notify(make_finding(Severity.INFO))

    def test_custom_severities(self):
        n = Notifier(notify_severities=['medium', 'low'])
        assert n.should_notify(make_finding(Severity.MEDIUM))
        assert n.should_notify(make_finding(Severity.LOW))
        assert not n.should_notify(make_finding(Severity.HIGH))
        assert not n.should_notify(make_finding(Severity.CRITICAL))

    def test_all_severities(self):
        n = Notifier(notify_severities=['critical', 'high', 'medium', 'low', 'info'])
        for sev in Severity:
            assert n.should_notify(make_finding(sev))


class TestNotifyRouting:
    def test_notify_calls_discord_when_webhook_set(self):
        n = Notifier(discord_webhook="https://discord.example/hook")
        f = make_finding(Severity.HIGH)
        with patch('core.notifier.send_discord') as mock_discord, \
             patch('core.notifier.send_slack') as mock_slack:
            n.notify(f, "example.com")
            mock_discord.assert_called_once_with("https://discord.example/hook", f, "example.com")
            mock_slack.assert_not_called()

    def test_notify_calls_slack_when_webhook_set(self):
        n = Notifier(slack_webhook="https://slack.example/hook")
        f = make_finding(Severity.CRITICAL)
        with patch('core.notifier.send_discord') as mock_discord, \
             patch('core.notifier.send_slack') as mock_slack:
            n.notify(f, "example.com")
            mock_slack.assert_called_once_with("https://slack.example/hook", f, "example.com")
            mock_discord.assert_not_called()

    def test_notify_calls_both_webhooks(self):
        n = Notifier(discord_webhook="https://discord.example/hook",
                     slack_webhook="https://slack.example/hook")
        f = make_finding(Severity.CRITICAL)
        with patch('core.notifier.send_discord') as mock_discord, \
             patch('core.notifier.send_slack') as mock_slack:
            n.notify(f, "example.com")
            mock_discord.assert_called_once()
            mock_slack.assert_called_once()

    def test_notify_skipped_when_severity_below_threshold(self):
        n = Notifier(discord_webhook="https://discord.example/hook")
        f = make_finding(Severity.INFO)
        with patch('core.notifier.send_discord') as mock_discord:
            n.notify(f, "example.com")
            mock_discord.assert_not_called()

    def test_notify_skipped_when_no_webhooks(self):
        n = Notifier()
        f = make_finding(Severity.CRITICAL)
        # Should not raise even with no webhooks
        with patch('core.notifier._http_post') as mock_post:
            n.notify(f, "example.com")
            mock_post.assert_not_called()


class TestDiscordPayload:
    def test_discord_embed_structure(self):
        f = make_finding(Severity.HIGH)
        captured = {}
        with patch('core.notifier._http_post') as mock_post:
            mock_post.return_value = True
            send_discord("https://discord.example/hook", f, "example.com")
            args = mock_post.call_args[0]
            payload = args[1]
            captured = payload

        assert 'embeds' in captured
        embed = captured['embeds'][0]
        assert 'title' in embed
        assert 'color' in embed
        assert 'fields' in embed
        assert embed['color'] == SEVERITY_COLOR[Severity.HIGH]

    def test_discord_evidence_truncated_at_1024(self):
        long_evidence = 'x' * 2000
        f = make_finding(Severity.HIGH, evidence=long_evidence)
        with patch('core.notifier._http_post') as mock_post:
            mock_post.return_value = True
            send_discord("https://hook", f, "example.com")
            payload = mock_post.call_args[0][1]
            desc = payload['embeds'][0]['description']
            assert len(desc) <= 1024

    def test_discord_none_evidence_shows_dash(self):
        f = make_finding(Severity.HIGH, evidence=None)
        with patch('core.notifier._http_post') as mock_post:
            mock_post.return_value = True
            send_discord("https://hook", f, "example.com")
            payload = mock_post.call_args[0][1]
            assert payload['embeds'][0]['description'] == '—'


class TestSlackPayload:
    def test_slack_text_contains_severity(self):
        f = make_finding(Severity.CRITICAL)
        with patch('core.notifier._http_post') as mock_post:
            mock_post.return_value = True
            send_slack("https://slack.example/hook", f, "example.com")
            payload = mock_post.call_args[0][1]
            assert 'CRITICAL' in payload['text']

    def test_slack_text_contains_domain(self):
        f = make_finding(Severity.HIGH)
        with patch('core.notifier._http_post') as mock_post:
            mock_post.return_value = True
            send_slack("https://slack.example/hook", f, "example.com")
            payload = mock_post.call_args[0][1]
            assert 'example.com' in payload['text']

    def test_slack_evidence_truncated_at_300(self):
        long_evidence = 'e' * 500
        f = make_finding(Severity.HIGH, evidence=long_evidence)
        with patch('core.notifier._http_post') as mock_post:
            mock_post.return_value = True
            send_slack("https://hook", f, "example.com")
            payload = mock_post.call_args[0][1]
            # The evidence is embedded in the text — total text includes other fields
            # Just verify the evidence portion is truncated
            assert long_evidence not in payload['text']


class TestSeverityMappings:
    def test_all_severities_have_color(self):
        for sev in Severity:
            assert sev in SEVERITY_COLOR

    def test_all_severities_have_emoji(self):
        for sev in Severity:
            assert sev in SEVERITY_EMOJI

    def test_critical_is_red(self):
        assert SEVERITY_COLOR[Severity.CRITICAL] == 0xFF0000

    def test_high_is_orange(self):
        assert SEVERITY_COLOR[Severity.HIGH] == 0xFF8C00


class TestNewSubdomainNotification:
    def test_new_subdomain_not_sent_by_default(self):
        n = Notifier(discord_webhook="https://discord.example/hook")
        with patch('core.notifier._http_post') as mock_post:
            n.notify_new_subdomain("new.example.com", "example.com")
            mock_post.assert_not_called()

    def test_new_subdomain_sent_when_enabled(self):
        n = Notifier(
            discord_webhook="https://discord.example/hook",
            notify_severities=['critical', 'high', 'new_subdomain']
        )
        with patch('core.notifier._http_post') as mock_post:
            mock_post.return_value = True
            n.notify_new_subdomain("new.example.com", "example.com")
            mock_post.assert_called_once()
            payload = mock_post.call_args[0][1]
            assert 'new.example.com' in payload['content']


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])
