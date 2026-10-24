"""Secrets are compared in constant time (vikunja#1219, same class as vikunja#759).

A behavioural test cannot see timing, so an ``==`` / ``!=`` that replaced
``hmac.compare_digest`` would pass every functional test. This walks the source of the
modules that compare bearer tokens and approval signatures and fails on any equality
comparison with a token, secret, password or signature operand.
"""

from __future__ import annotations

import ast
import hmac
import re
from pathlib import Path
from unittest.mock import patch

import pytest

import scoped_mcp

_PKG = Path(scoped_mcp.__file__).parent
_FILES = ["http_auth.py", "hitl_signing.py"]
_SECRET_NAME = re.compile(r"token|secret|passw|signature|bearer", re.IGNORECASE)


def _names(node: ast.AST) -> set[str]:
    out: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            out.add(sub.id)
        elif isinstance(sub, ast.Attribute):
            out.add(sub.attr)
        elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            out.add(sub.value)  # subscript keys: statement["signature"]
    return out


def _secret_equality_compares(source: str) -> list[tuple[int, str]]:
    found = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Compare):
            continue
        if not any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
            continue
        operands = [node.left, *node.comparators]
        # A comparison against None or a literal is a presence check, not a secret compare.
        if any(isinstance(o, ast.Constant) for o in operands):
            continue
        hits = {n for o in operands for n in _names(o) if _SECRET_NAME.search(n)}
        if hits:
            found.append((node.lineno, ", ".join(sorted(hits))))
    return found


@pytest.mark.parametrize("filename", _FILES)
def test_no_equality_compare_on_secret_operands(filename: str) -> None:
    found = _secret_equality_compares((_PKG / filename).read_text())
    assert found == [], f"{filename}: use hmac.compare_digest, not ==/!=, at {found}"


def test_detector_flags_the_timing_unsafe_form() -> None:
    """Guard: the walker must actually see the mutation it exists to catch."""
    unsafe = "if not token or token.encode() != self._expected_token.encode():\n    pass\n"
    safe = (
        "if not token or not hmac.compare_digest(token.encode(), "
        "self._expected_token.encode()):\n    pass\n"
    )
    assert _secret_equality_compares(unsafe)
    assert _secret_equality_compares(safe) == []


async def test_bearer_verifier_calls_compare_digest() -> None:
    from scoped_mcp.http_auth import BearerTokenVerifier

    verifier = BearerTokenVerifier(expected_token="placeholder-token", agent_id="dev")
    with patch("scoped_mcp.http_auth.hmac.compare_digest", wraps=hmac.compare_digest) as spy:
        assert await verifier.verify_token("placeholder-token") is not None
        assert await verifier.verify_token("wrong-token-xx") is None
    assert spy.call_count == 2
