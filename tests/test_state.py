"""Tests for ServerState: config-file disabled flag + runtime enable/disable."""

import json
from pathlib import Path

import pytest

from mcp_launchpad.config import Config, ServerConfig, parse_server_config
from mcp_launchpad.state import ServerState


@pytest.fixture
def config_with_disabled() -> Config:
    """Config with one enabled and one config-disabled server."""
    return Config(
        servers={
            "active": ServerConfig(name="active", command="test"),
            "dormant": ServerConfig(name="dormant", command="test", disabled=True),
        },
        config_path=Path("/some/.mcp.json"),
    )


class TestParseDisabledField:
    """Parsing of the "disabled" field from config JSON."""

    def test_default_is_enabled(self):
        server = parse_server_config("s", {"command": "test"})
        assert server.disabled is False

    def test_disabled_true_parsed(self):
        server = parse_server_config("s", {"command": "test", "disabled": True})
        assert server.disabled is True

    def test_disabled_false_parsed(self):
        server = parse_server_config("s", {"command": "test", "disabled": False})
        assert server.disabled is False


class TestConfigDisabled:
    """Declarative disable via the config file."""

    def test_is_disabled_from_config(self, isolated_state, config_with_disabled):
        state = ServerState(config_with_disabled)
        assert state.is_disabled("dormant")
        assert state.is_enabled("active")

    def test_disabled_source_config(self, isolated_state, config_with_disabled):
        state = ServerState(config_with_disabled)
        assert state.disabled_source("dormant") == "config"
        assert state.disabled_source("active") is None

    def test_get_enabled_excludes_config_disabled(
        self, isolated_state, config_with_disabled
    ):
        state = ServerState(config_with_disabled)
        assert list(state.get_enabled_servers()) == ["active"]
        assert state.get_disabled_servers() == ["dormant"]

    def test_enable_cannot_override_config(self, isolated_state, config_with_disabled):
        state = ServerState(config_with_disabled)
        with pytest.raises(ValueError, match="disabled in"):
            state.enable("dormant")
        # Still disabled afterwards
        assert state.is_disabled("dormant")

    def test_to_dict_counts_config_disabled(self, isolated_state, config_with_disabled):
        state = ServerState(config_with_disabled)
        d = state.to_dict()
        assert d["disabled_servers"] == ["dormant"]
        assert d["enabled_count"] == 1
        assert d["disabled_count"] == 1


class TestRuntimeDisabled:
    """Runtime disable via `mcpl disable` (persisted state file)."""

    def test_disable_enable_roundtrip(self, isolated_state, config_with_disabled):
        state = ServerState(config_with_disabled)
        assert state.disable("active") is True
        assert state.is_disabled("active")
        assert state.disabled_source("active") == "runtime"
        # Persisted
        data = json.loads(isolated_state.read_text())
        assert data["disabled_servers"] == ["active"]

        assert state.enable("active") is True
        assert state.is_enabled("active")
        data = json.loads(isolated_state.read_text())
        assert data["disabled_servers"] == []

    def test_disable_unknown_server_raises(self, isolated_state, config_with_disabled):
        state = ServerState(config_with_disabled)
        with pytest.raises(ValueError, match="not found"):
            state.disable("ghost")
        with pytest.raises(ValueError, match="not found"):
            state.enable("ghost")

    def test_both_sources_config_wins_in_reporting(
        self, isolated_state, config_with_disabled
    ):
        state = ServerState(config_with_disabled)
        state.disable("dormant")  # runtime on top of config
        assert state.disabled_source("dormant") == "config"
        assert state.get_disabled_servers() == ["dormant"]

    def test_stale_runtime_entries_dropped(self, isolated_state, config_with_disabled):
        isolated_state.parent.mkdir(parents=True)
        isolated_state.write_text(json.dumps({"disabled_servers": ["gone", "active"]}))
        state = ServerState(config_with_disabled)
        assert state.is_disabled("active")
        assert "gone" not in state.get_disabled_servers()
