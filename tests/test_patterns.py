"""Tests for pattern detection (M07)."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.m12_pattern import PatternModule
from unittest.mock import MagicMock


def make_module():
    config = MagicMock()
    # Return sensible defaults for different key types
    def mock_get(*args, **kwargs):
        default = kwargs.get('default', None)
        # log_level needs to be a string
        if 'log_level' in args:
            return 'INFO'
        if 'log_file' in args:
            return None
        return default
    config.get.side_effect = mock_get
    db = MagicMock()
    m = PatternModule(config, db)
    return m


def test_aws_key_detection():
    m = make_module()
    urls = [
        "https://example.com/api?key=\x41KIAIOSFODNN7EXAMPLEKEY123456",
        "https://example.com/normal?page=1"
    ]
    matches = m._scan_urls(urls)
    aws_matches = [x for x in matches if 'aws' in x.get('pattern', '').lower()]
    assert len(aws_matches) >= 1


def test_git_exposed():
    m = make_module()
    urls = ["https://example.com/.git/config", "https://example.com/index.php"]
    matches = m._scan_urls(urls)
    git = [x for x in matches if 'git' in x.get('pattern', '').lower()]
    assert len(git) >= 1


def test_env_file():
    m = make_module()
    urls = ["https://example.com/.env", "https://example.com/.env.production"]
    matches = m._scan_urls(urls)
    env = [x for x in matches if 'env' in x.get('pattern', '').lower()]
    assert len(env) >= 1


def test_redirect_param():
    m = make_module()
    urls = [
        "https://example.com/login?redirect=https://evil.com",
        "https://example.com/sso?return=/dashboard"
    ]
    matches = m._scan_urls(urls)
    redirects = [x for x in matches if 'redirect' in x.get('pattern', '').lower()]
    assert len(redirects) >= 1


def test_no_false_positives_on_clean_url():
    m = make_module()
    urls = ["https://example.com/about", "https://example.com/products/widget"]
    matches = m._scan_urls(urls)
    critical = [x for x in matches if x.get('severity') == 'critical']
    assert len(critical) == 0


if __name__ == '__main__':
    test_aws_key_detection()
    test_git_exposed()
    test_env_file()
    test_redirect_param()
    test_no_false_positives_on_clean_url()
    print("✅ All pattern tests passed")
