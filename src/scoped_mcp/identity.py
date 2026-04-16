"""Agent identity — reads AGENT_ID and AGENT_TYPE from the environment."""

from __future__ import annotations

import os
from dataclasses import dataclass

from .exceptions import ConfigError


@dataclass(frozen=True)
class AgentContext:
    """Immutable identity for the running agent.

    Created once at startup and passed to every module. All scope decisions
    are keyed on agent_id; agent_type drives manifest selection conventions.
    """

    agent_id: str
    agent_type: str

    @classmethod
    def from_env(cls) -> "AgentContext":
        """Build an AgentContext from environment variables.

        Raises ConfigError if AGENT_ID or AGENT_TYPE is missing or empty.
        """
        agent_id = os.environ.get("AGENT_ID", "").strip()
        agent_type = os.environ.get("AGENT_TYPE", "").strip()

        pairs = [("AGENT_ID", agent_id), ("AGENT_TYPE", agent_type)]
        missing = [name for name, val in pairs if not val]
        if missing:
            raise ConfigError(f"Required environment variable(s) not set: {', '.join(missing)}")

        return cls(agent_id=agent_id, agent_type=agent_type)
