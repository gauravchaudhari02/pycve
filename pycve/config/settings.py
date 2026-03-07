"""Configuration management for pycve."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from pycve.utils.exceptions import ConfigError

# Default config directory: ~/.pycve/
_DEFAULT_CONFIG_DIR = Path.home() / ".pycve"
_DEFAULT_CONFIG_FILE = _DEFAULT_CONFIG_DIR / "config.yaml"

_DEFAULTS: dict[str, Any] = {
    "api_key": None,
    "cache_ttl": 86400,            # 24 hours
    "default_report_format": "json",
    "output_dir": ".",
    "slack_webhook_url": None,
    "teams_webhook_url": None,
}

# Env var → config key mapping
_ENV_VARS: dict[str, str] = {
    "NVD_API_KEY": "api_key",
    "PYCVE_CACHE_TTL": "cache_ttl",
    "PYCVE_SLACK_WEBHOOK": "slack_webhook_url",
    "PYCVE_TEAMS_WEBHOOK": "teams_webhook_url",
}


class ConfigManager:
    """YAML-based configuration management with env-var and constructor overrides.

    Precedence (highest → lowest):
      1. Constructor ``overrides`` dict
      2. Environment variables (``NVD_API_KEY``, ``PYCVE_*``)
      3. Config file at ``~/.pycve/config.yaml``
      4. Built-in defaults
    """

    def __init__(
        self,
        config_path: str | Path | None = None,
        overrides: dict[str, Any] | None = None,
    ):
        self._config_path = Path(config_path) if config_path else _DEFAULT_CONFIG_FILE
        self._overrides: dict[str, Any] = overrides or {}
        self._file_config: dict[str, Any] = {}
        self._load()

    # ── Internal ─────────────────────────────────────────────────────────────

    def _load(self) -> None:
        """Load config from YAML file; silently skip if not present."""
        if self._config_path.exists():
            try:
                with self._config_path.open() as f:
                    data = yaml.safe_load(f) or {}
                self._file_config = {k: v for k, v in data.items() if k in _DEFAULTS}
            except Exception as exc:
                raise ConfigError(f"Failed to read config file {self._config_path}: {exc}") from exc

    def _save(self) -> None:
        """Persist the current file config to YAML."""
        try:
            self._config_path.parent.mkdir(parents=True, exist_ok=True)
            with self._config_path.open("w") as f:
                yaml.safe_dump(self._file_config, f, default_flow_style=False)
        except Exception as exc:
            raise ConfigError(f"Failed to write config file {self._config_path}: {exc}") from exc

    # ── Public API ───────────────────────────────────────────────────────────

    def get(self, key: str) -> Any:
        """Return the effective value for *key* following precedence rules."""
        if key not in _DEFAULTS:
            raise ConfigError(f"Unknown config key: '{key}'. Valid keys: {list(_DEFAULTS)}")
        # 1. Constructor override
        if key in self._overrides and self._overrides[key] is not None:
            return self._overrides[key]
        # 2. Environment variable
        for env, cfg_key in _ENV_VARS.items():
            if cfg_key == key:
                val = os.environ.get(env)
                if val:
                    # Coerce numeric values
                    try:
                        return int(val) if isinstance(_DEFAULTS[key], int) else val
                    except ValueError:
                        return val
        # 3. Config file
        if key in self._file_config:
            return self._file_config[key]
        # 4. Default
        return _DEFAULTS[key]

    def set(self, key: str, value: Any) -> None:
        """Persist *value* for *key* to the config file."""
        if key not in _DEFAULTS:
            raise ConfigError(f"Unknown config key: '{key}'. Valid keys: {list(_DEFAULTS)}")
        self._file_config[key] = value
        self._save()

    def list(self) -> dict[str, Any]:
        """Return a dict of all keys with their current effective values."""
        return {key: self.get(key) for key in _DEFAULTS}

    def reset(self, key: str | None = None) -> None:
        """Reset *key* (or all keys if ``None``) to defaults and save."""
        if key is not None:
            if key not in _DEFAULTS:
                raise ConfigError(f"Unknown config key: '{key}'")
            self._file_config.pop(key, None)
        else:
            self._file_config.clear()
        self._save()

    def __repr__(self) -> str:
        return f"ConfigManager(path={self._config_path!r})"
