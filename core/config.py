"""Argus V2 - Configuration Loader"""

import yaml
import os
import re
from pathlib import Path
from typing import Any, Optional


# Recognised env-file line: KEY=value, optional leading `export`, optional
# quoted value. We are deliberately strict — no multiline strings, no
# variable expansion. Anything more elaborate belongs in h4wk3y3.yaml.
_ENV_LINE_RE = re.compile(
    r'^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*$'
)


def _load_env_file(path: Path) -> dict:
    """Parse a .env-style file. Empty lines and `#` comments ignored.
    Returns a dict of {KEY: value} where value has surrounding quotes
    stripped. Missing file → empty dict (not an error)."""
    out: dict = {}
    if not path.exists():
        return out
    for raw in path.read_text().splitlines():
        if not raw.strip() or raw.lstrip().startswith('#'):
            continue
        m = _ENV_LINE_RE.match(raw)
        if not m:
            continue
        k, v = m.group(1), m.group(2)
        if v and v[0] == v[-1] and v[0] in ('"', "'"):
            v = v[1:-1]
        out[k] = v
    return out


class ArgusConfig:
    """Loads and provides access to h4wk3y3.yaml configuration.

    Secrets policy:
      - h4wk3y3.yaml is version-controlled. Do NOT put API keys there.
      - Put keys in h4wk3y3.env (sibling file, gitignored). They are
        exported into os.environ at load time so modules that read
        env vars (m01 OSINT, chaos, etc.) pick them up transparently.
    """

    DEFAULT_CONFIG = Path(__file__).parent.parent / "config" / "h4wk3y3.yaml"

    def __init__(self, config_path: Optional[str] = None):
        self._path = Path(config_path) if config_path else self.DEFAULT_CONFIG
        self._data = self._load()
        self._load_env()

    def _load(self) -> dict:
        if not self._path.exists():
            raise FileNotFoundError(f"Config not found: {self._path}")
        with open(self._path) as f:
            return yaml.safe_load(f)

    def _load_env(self) -> None:
        """Load sibling h4wk3y3.env (if present). Existing os.environ values
        win over the file — runtime env should always override on-disk."""
        env_path = self._path.with_suffix('.env')
        env = _load_env_file(env_path)
        for k, v in env.items():
            if k not in os.environ:  # do not clobber an existing env var
                os.environ[k] = v

    @property
    def path(self) -> Path:
        return self._path

    @property
    def data(self) -> dict:
        return self._data

    def reload(self) -> None:
        """Re-read the YAML from disk. Used by the dashboard's config UI
        after the user edits the file via the API. Each spawned scan
        re-reads the YAML on its own, so this only refreshes the
        dashboard process's view (output_dir, log_level, etc.)."""
        self._data = self._load()

    def get(self, *keys: str, default: Any = None) -> Any:
        """Dot-path access: config.get('subdomain', 'active', 'enabled')"""
        node = self._data
        for k in keys:
            if not isinstance(node, dict) or k not in node:
                return default
            node = node[k]
        return node

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def output_dir(self, domain: str) -> Path:
        base = Path(self.get('general', 'output_dir', default='./output'))
        path = base / domain
        path.mkdir(parents=True, exist_ok=True)
        return path

    def api_key(self, service: str) -> Optional[str]:
        key = self.get('api_keys', service, default='')
        # Also check environment variable: ARGUS_<SERVICE>_KEY
        env_key = os.getenv(f'ARGUS_{service.upper()}_KEY', '')
        return env_key or key or None
