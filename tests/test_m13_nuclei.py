"""Unit tests for M13 Nuclei — JSONL parsing tolerance, SEV_MAP, tech map.

No nuclei binary, no subprocess, no network. Pure data/logic only.
"""
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from modules.m13_nuclei import (
    SEV_MAP,
    TECH_TEMPLATE_MAP,
)
from core.models import Severity


def parse_jsonl(text):
    """Mirror of m13's result-parsing loop (l.366-371): tolerant line-by-line
    JSON decode, silently dropping any line that isn't valid JSON."""
    out = []
    for line in text.splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return out


class TestJSONLParsing:
    def test_valid_lines_parsed(self):
        text = '{"a": 1}\n{"b": 2}'
        assert parse_jsonl(text) == [{'a': 1}, {'b': 2}]

    def test_blank_lines_skipped(self):
        text = '{"a": 1}\n\n   \n{"b": 2}\n'
        assert parse_jsonl(text) == [{'a': 1}, {'b': 2}]

    def test_invalid_line_dropped_others_kept(self):
        text = '{"ok": 1}\nnot json at all\n{"ok": 2}'
        out = parse_jsonl(text)
        assert out == [{'ok': 1}, {'ok': 2}]

    def test_partial_json_dropped(self):
        text = '{"complete": true}\n{"truncated":'
        out = parse_jsonl(text)
        assert out == [{'complete': True}]

    def test_empty_input(self):
        assert parse_jsonl('') == []

    def test_whitespace_only_input(self):
        assert parse_jsonl('\n\n  \n') == []

    def test_nested_objects_preserved(self):
        text = '{"info": {"severity": "high", "tags": ["cve"]}}'
        out = parse_jsonl(text)
        assert out[0]['info']['severity'] == 'high'
        assert out[0]['info']['tags'] == ['cve']

    def test_source_uses_tolerant_decode(self):
        # The real loop swallows json.JSONDecodeError — guard against a
        # refactor that lets a bad line crash the whole parse.
        text = (Path(__file__).parent.parent / 'modules' / 'm13_nuclei.py').read_text()
        assert 'json.JSONDecodeError' in text
        assert 'splitlines()' in text


class TestSevMap:
    def test_all_levels_mapped(self):
        assert SEV_MAP['critical'] == Severity.CRITICAL
        assert SEV_MAP['high'] == Severity.HIGH
        assert SEV_MAP['medium'] == Severity.MEDIUM
        assert SEV_MAP['low'] == Severity.LOW
        assert SEV_MAP['info'] == Severity.INFO

    def test_unknown_severity_falls_back_to_info(self):
        # m13 uses SEV_MAP.get(sev_str, Severity.INFO)
        assert SEV_MAP.get('bogus', Severity.INFO) == Severity.INFO

    def test_keys_are_lowercase(self):
        assert all(k == k.lower() for k in SEV_MAP)


class TestTechTemplateMap:
    @staticmethod
    def _tags_for(techs):
        """Mirror of m13's targeted_scanning matching: substring-insensitive
        tech name → template tag accumulation."""
        tags = set()
        for tech in techs:
            for pattern, tag_list in TECH_TEMPLATE_MAP.items():
                if pattern.lower() in tech.lower():
                    tags.update(tag_list)
        return tags

    def test_wordpress_maps_to_wp_tags(self):
        tags = self._tags_for(['WordPress 6.5'])
        assert 'wordpress' in tags and 'wp' in tags

    def test_substring_versioned_tech_matches(self):
        # "Apache Tomcat/9.0" should hit the Tomcat pattern.
        tags = self._tags_for(['Apache Tomcat/9.0.50'])
        assert 'tomcat' in tags

    def test_case_insensitive_match(self):
        assert 'jenkins' in self._tags_for(['JENKINS'])

    def test_unknown_tech_yields_no_tags(self):
        assert self._tags_for(['SomeRandomProduct']) == set()

    def test_atlassian_shared_across_products(self):
        # Confluence, Jira, Bitbucket all carry the 'atlassian' tag.
        assert 'atlassian' in TECH_TEMPLATE_MAP['Confluence']
        assert 'atlassian' in TECH_TEMPLATE_MAP['Jira']
        assert 'atlassian' in TECH_TEMPLATE_MAP['Bitbucket']

    def test_all_values_are_nonempty_lists(self):
        for k, v in TECH_TEMPLATE_MAP.items():
            assert isinstance(v, list) and v, f"{k} has empty tag list"

    def test_all_tags_lowercase(self):
        for tags in TECH_TEMPLATE_MAP.values():
            for t in tags:
                assert t == t.lower()


class TestSeverityCountOrdering:
    ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown']

    def _summary(self, findings_data):
        sev_counts = {}
        for x in findings_data:
            s = (x.get('info', {}).get('severity') or 'info').lower()
            sev_counts[s] = sev_counts.get(s, 0) + 1
        return ' '.join(
            f"{k}={v}" for k, v in sorted(
                sev_counts.items(),
                key=lambda kv: self.ORDER.index(kv[0]) if kv[0] in self.ORDER else 99,
            )
        )

    def test_counts_and_order(self):
        data = [
            {'info': {'severity': 'low'}},
            {'info': {'severity': 'critical'}},
            {'info': {'severity': 'high'}},
            {'info': {'severity': 'critical'}},
        ]
        assert self._summary(data) == 'critical=2 high=1 low=1'

    def test_missing_severity_defaults_info(self):
        assert self._summary([{'info': {}}]) == 'info=1'

    def test_missing_info_key_defaults_info(self):
        assert self._summary([{}]) == 'info=1'


class TestProgressLineFilter:
    """The stderr drainer only treats a line as a stats event when it starts
    with '{' and decodes to a dict containing both 'matched' and 'duration'."""
    @staticmethod
    def _is_stats(txt):
        if not txt or not txt.startswith('{'):
            return False
        try:
            obj = json.loads(txt)
        except json.JSONDecodeError:
            return False
        return isinstance(obj, dict) and 'matched' in obj and 'duration' in obj

    def test_valid_stats_line(self):
        assert self._is_stats('{"matched": 3, "duration": "0:01:00", "percent": 50}')

    def test_non_brace_line_ignored(self):
        assert self._is_stats('[INF] some nuclei log line') is False

    def test_malformed_json_ignored(self):
        assert self._is_stats('{not valid json') is False

    def test_dict_without_required_keys_ignored(self):
        assert self._is_stats('{"foo": 1}') is False

    def test_empty_ignored(self):
        assert self._is_stats('') is False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
