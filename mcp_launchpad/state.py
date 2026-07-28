"""Server state management for mcpl-controlled enable/disable."""

import json
from pathlib import Path
from typing import Any

from .config import Config

# State file location (same directory as cache)
STATE_DIR = Path.home() / ".cache" / "mcp-launchpad"
STATE_FILE = STATE_DIR / "server_state.json"


class ServerState:
    """Manages the enabled/disabled state of MCP servers.

    A server is disabled if EITHER source says so:
    - Declarative: ``"disabled": true`` on the server entry in the config file
      (versioned, per-project; edit the file to change it).
    - Runtime: ``mcpl disable <server>`` (per-machine, persisted in the state
      file under ~/.cache/mcp-launchpad/).

    By default, all servers in the config are enabled.
    """

    def __init__(self, config: Config):
        self.config = config
        self.state_file = STATE_FILE
        self._disabled_servers: set[str] = set()
        self._load()

    def _ensure_state_dir(self) -> None:
        """Ensure state directory exists."""
        STATE_DIR.mkdir(parents=True, exist_ok=True)

    def _load(self) -> None:
        """Load state from file."""
        if not self.state_file.exists():
            self._disabled_servers = set()
            return

        try:
            with open(self.state_file) as f:
                data = json.load(f)
                # Only keep disabled servers that still exist in config
                self._disabled_servers = {
                    s
                    for s in data.get("disabled_servers", [])
                    if s in self.config.servers
                }
        except (json.JSONDecodeError, KeyError):
            self._disabled_servers = set()

    def _save(self) -> None:
        """Save state to file."""
        self._ensure_state_dir()
        with open(self.state_file, "w") as f:
            json.dump({"disabled_servers": sorted(self._disabled_servers)}, f, indent=2)

    def _config_disabled(self, server_name: str) -> bool:
        """Check if a server is disabled declaratively in the config file."""
        server = self.config.servers.get(server_name)
        return server is not None and server.disabled

    def disabled_source(self, server_name: str) -> str | None:
        """Return why a server is disabled: 'config', 'runtime', or None.

        'config' takes precedence in reporting because it cannot be
        overridden by `mcpl enable` - the user must edit the config file.
        """
        if self._config_disabled(server_name):
            return "config"
        if server_name in self._disabled_servers:
            return "runtime"
        return None

    def is_enabled(self, server_name: str) -> bool:
        """Check if a server is enabled."""
        return not self.is_disabled(server_name)

    def is_disabled(self, server_name: str) -> bool:
        """Check if a server is disabled (config file OR runtime state)."""
        return self.disabled_source(server_name) is not None

    def enable(self, server_name: str) -> bool:
        """Enable a server. Returns True if state changed.

        Raises ValueError if the server is unknown, or if it is disabled
        declaratively in the config file (runtime enable cannot override it).
        """
        if server_name not in self.config.servers:
            raise ValueError(f"Server '{server_name}' not found in config")

        if self._config_disabled(server_name):
            config_path = self.config.config_path or "the config file"
            raise ValueError(
                f"Server '{server_name}' is disabled in {config_path} "
                f'("disabled": true). Remove that line to re-enable it.'
            )

        if server_name in self._disabled_servers:
            self._disabled_servers.remove(server_name)
            self._save()
            return True
        return False

    def disable(self, server_name: str) -> bool:
        """Disable a server at runtime. Returns True if state changed."""
        if server_name not in self.config.servers:
            raise ValueError(f"Server '{server_name}' not found in config")

        if server_name not in self._disabled_servers:
            self._disabled_servers.add(server_name)
            self._save()
            return True
        return False

    def get_enabled_servers(self) -> dict[str, Any]:
        """Get dict of enabled server names to their configs."""
        return {
            name: cfg
            for name, cfg in self.config.servers.items()
            if self.is_enabled(name)
        }

    def get_disabled_servers(self) -> list[str]:
        """Get sorted list of disabled server names (both sources)."""
        return sorted(
            name for name in self.config.servers if self.is_disabled(name)
        )

    def to_dict(self) -> dict[str, Any]:
        """Get state as a dictionary."""
        disabled = self.get_disabled_servers()
        return {
            "disabled_servers": disabled,
            "enabled_count": len(self.config.servers) - len(disabled),
            "disabled_count": len(disabled),
        }
