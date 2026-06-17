"""Tests for ArgusConfig — YAML loading, env overrides, output_dir."""
import sys
import os
import tempfile
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parent.parent))

from core.config import ArgusConfig


def test_default_config():
    cfg = ArgusConfig()
    # Default output dir
    out = cfg.get('general', 'output_dir', default='./output')
    assert out == './output'

def test_get_nested_default():
    cfg = ArgusConfig()
    val = cfg.get('subdomain', 'passive', 'subfinder', default=True)
    assert val is True

def test_get_missing_key_returns_default():
    cfg = ArgusConfig()
    val = cfg.get('nonexistent_section', 'nonexistent_key', default='fallback')
    assert val == 'fallback'

def test_output_dir_creates_path():
    cfg = ArgusConfig()
    with tempfile.TemporaryDirectory() as tmp:
        # Patch output dir
        cfg._data.setdefault('general', {})['output_dir'] = tmp
        out = cfg.output_dir('testdomain.com')
        assert out.exists()
        assert out.name == 'testdomain.com'

def test_yaml_custom_config():
    """Config chargée depuis un fichier YAML custom."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write("general:\n  log_level: DEBUG\n  output_dir: /tmp/argus_test\n")
        tmp = f.name
    try:
        cfg = ArgusConfig(tmp)
        assert cfg.get('general', 'log_level', default='INFO') == 'DEBUG'
    finally:
        os.unlink(tmp)
