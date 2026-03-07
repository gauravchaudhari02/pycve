"""Tests for pycve.config.settings."""

from __future__ import annotations

import os

import pytest

from pycve.config.settings import ConfigManager
from pycve.utils.exceptions import ConfigError


@pytest.fixture
def config(tmp_path):
    return ConfigManager(config_path=tmp_path / "config.yaml")


class TestConfigManager:
    def test_default_values(self, config):
        assert config.get("cache_ttl") == 86400
        assert config.get("default_report_format") == "json"
        assert config.get("api_key") is None

    def test_set_and_get(self, config):
        config.set("api_key", "test-key-123")
        assert config.get("api_key") == "test-key-123"

    def test_persists_to_yaml(self, tmp_path):
        cfg_path = tmp_path / "config.yaml"
        c1 = ConfigManager(config_path=cfg_path)
        c1.set("api_key", "persistent-key")
        # Create new instance reading same file
        c2 = ConfigManager(config_path=cfg_path)
        assert c2.get("api_key") == "persistent-key"

    def test_env_var_override(self, config, monkeypatch):
        monkeypatch.setenv("NVD_API_KEY", "env-key")
        assert config.get("api_key") == "env-key"

    def test_constructor_override_beats_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NVD_API_KEY", "env-key")
        cfg = ConfigManager(config_path=tmp_path / "cfg.yaml", overrides={"api_key": "ctor-key"})
        assert cfg.get("api_key") == "ctor-key"

    def test_list_returns_all_keys(self, config):
        settings = config.list()
        assert "api_key" in settings
        assert "cache_ttl" in settings
        assert "slack_webhook_url" in settings

    def test_reset_single_key(self, config):
        config.set("cache_ttl", 9999)
        config.reset("cache_ttl")
        assert config.get("cache_ttl") == 86400  # back to default

    def test_reset_all(self, config):
        config.set("api_key", "key")
        config.set("cache_ttl", 9999)
        config.reset()
        assert config.get("api_key") is None
        assert config.get("cache_ttl") == 86400

    def test_unknown_key_raises(self, config):
        with pytest.raises(ConfigError):
            config.get("unknown_key_xyz")

    def test_set_unknown_key_raises(self, config):
        with pytest.raises(ConfigError):
            config.set("unknown_key_xyz", "value")

    def test_repr_contains_path(self, config, tmp_path):
        r = repr(config)
        assert "ConfigManager" in r
        assert "config.yaml" in r

    def test_broken_yaml_raises_config_error(self, tmp_path):
        cfg_path = tmp_path / "broken.yaml"
        cfg_path.write_text("api_key: [\ninvalid yaml")
        with pytest.raises(ConfigError):
            ConfigManager(config_path=cfg_path)
