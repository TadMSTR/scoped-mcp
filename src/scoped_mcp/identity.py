"""Agent identity — reads AGENT_ID and AGENT_TYPE from the environment.

Security model (2026-04-16 audit, finding M5):
``agent_id`` is interpolated into filesystem paths, bucket prefixes, folder
titles, and log fields across the codebase. Anything containing ``/``, ``..``,
whitespace, or shell metacharacters breaks the trust boundary. ``from_env``
validates both identifiers against a conservative pattern before constructing
the ``AgentContext`` — callers that build one directly are responsible for
passing pre-validated values.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from .exceptions import ConfigError

_AGENT_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_AGENT_TYPE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


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

        Raises ConfigError if AGENT_ID or AGENT_TYPE is missing, empty, or
        does not match the allowed identifier pattern.
        """
        agent_id = os.environ.get("AGENT_ID", "").strip()
        agent_type = os.environ.get("AGENT_TYPE", "").strip()

        pairs = [("AGENT_ID", agent_id), ("AGENT_TYPE", agent_type)]
        missing = [name for name, val in pairs if not val]
        if missing:
            raise ConfigError(f"Required environment variable(s) not set: {', '.join(missing)}")

        if not _AGENT_ID_PATTERN.match(agent_id):
            raise ConfigError(
                f"AGENT_ID {agent_id!r} does not match required pattern "
                f"{_AGENT_ID_PATTERN.pattern}. Must be 1–63 characters of "
                f"lowercase a–z / digits / hyphen and start with a letter or digit."
            )
        if not _AGENT_TYPE_PATTERN.match(agent_type):
            raise ConfigError(
                f"AGENT_TYPE {agent_type!r} does not match required pattern "
                f"{_AGENT_TYPE_PATTERN.pattern}. Must be 1–63 characters of "
                f"lowercase a–z / digits / hyphen / underscore and start with a "
                f"letter or digit."
            )

        return cls(agent_id=agent_id, agent_type=agent_type)
