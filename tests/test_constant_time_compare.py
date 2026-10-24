"""Secrets are compared in constant time (vikunja#1219, same class as vikunja#759).

A behavioural test cannot see timing, so an ``==`` / ``!=`` that replaced
``hmac.compare_digest`` would pass every functional test. Two structural checks:

- every function known to compare a secret must still call ``hmac.compare_digest``, and every
  ``compare_digest`` call in ``src/`` must belong to a known function, so a new site is
  registered here rather than silently unpinned;
- no ``==`` / ``!=`` in ``src/`` has an operand whose name looks like a secret.

The registry is what pins a swap: the mutant removes the ``compare_digest`` call, so nothing
derived from those calls can find it. The name walk is the second net for new code.
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

# (file relative to the package, function) for every secret compare in src/.
_CONSTANT_TIME_SITES = {
    ("http_auth.py", "verify_token"),  # per-agent HTTP bearer
    ("hitl_http.py", "_check_bearer"),  # /hitl/* endpoint bearer
    ("hitl_endpoint.py", "approve"),  # Phase 2 courier OTP
}

_SECRET_NAME = re.compile(
    r"token|secret|passw|signature|^sig$|otp|presented|expected|digest|hmac|^mac$|bearer",
    re.IGNORECASE,
)


# Equality compares whose operand names match _SECRET_NAME but hold no secret. Keyed on
# (file, matched names) so a new compare on a secret in the same file is still caught.
_NOT_SECRETS = {
    # A boolean health flag, not a token.
    ("credentials_vault.py", "token_healthy"): "renewal health edge detection",
    # SHA-256 of the approval's arguments, which the approver already holds: integrity, not
    # secrecy, so there is no value for a timing side channel to recover.
    ("hitl.py", "digest"): "args digest vs the unhashable sentinel",
    ("hitl_approver.py", "digest"): "stored args digest vs a recomputed one",
}


def _sources() -> dict[str, ast.AST]:
    return {str(p.relative_to(_PKG)): ast.parse(p.read_text()) for p in sorted(_PKG.rglob("*.py"))}


def _calls_compare_digest(node: ast.AST) -> bool:
    return any(
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "compare_digest"
        for n in ast.walk(node)
    )


def _functions(tree: ast.AST) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _names(node: ast.AST) -> set[str]:
    out: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            out.add(sub.id)
        elif isinstance(sub, ast.Attribute):
            out.add(sub.attr.lstrip("_"))
        elif isinstance(sub, ast.Subscript) and isinstance(sub.slice, ast.Constant):
            if isinstance(sub.slice.value, str):
                out.add(sub.slice.value)  # statement["signature"]
    return out


def _is_presence_check(node: ast.AST) -> bool:
    """Comparisons against None or "" are presence checks and carry no secret timing."""
    return isinstance(node, ast.Constant) and node.value in (None, "", b"")


def _secret_equality_compares(tree: ast.AST) -> list[tuple[int, str]]:
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        if not any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
            continue
        operands = [node.left, *node.comparators]
        if any(_is_presence_check(o) for o in operands):
            continue
        hits = {n for o in operands for n in _names(o) if _SECRET_NAME.search(n)}
        if hits:
            found.append((node.lineno, ", ".join(sorted(hits))))
    return found


@pytest.mark.parametrize(("filename", "function"), sorted(_CONSTANT_TIME_SITES))
def test_known_secret_compares_still_use_compare_digest(filename: str, function: str) -> None:
    tree = _sources()[filename]
    matches = [f for f in _functions(tree) if f.name == function]
    assert matches, f"{filename}:{function} not found; update _CONSTANT_TIME_SITES"
    assert any(_calls_compare_digest(f) for f in matches), (
        f"{filename}:{function} no longer calls hmac.compare_digest"
    )


def test_every_compare_digest_site_is_registered() -> None:
    """A new compare_digest call has to be added to the registry, so it is pinned too."""
    sites = set()
    for filename, tree in _sources().items():
        for fn in _functions(tree):
            inner = [n for n in _functions(fn) if n is not fn]
            if _calls_compare_digest(fn) and not any(_calls_compare_digest(d) for d in inner):
                sites.add((filename, fn.name))
    assert sites == _CONSTANT_TIME_SITES


def test_no_equality_compare_on_secret_operands() -> None:
    found = {
        filename: unexpected
        for filename, tree in _sources().items()
        if (
            unexpected := [
                (line, names)
                for line, names in _secret_equality_compares(tree)
                if (filename, names) not in _NOT_SECRETS
            ]
        )
    }
    assert found == {}, f"use hmac.compare_digest, not ==/!=: {found}"


@pytest.mark.parametrize(
    "source",
    [
        "if not token or token.encode() != self._expected_token.encode():\n    pass\n",
        "if not presented or presented != expected:\n    pass\n",
        "if stored_otp is None or otp != stored_otp:\n    pass\n",
        "ok = sig == expected_sig\n",
        'ok = token == "fixed-secret"\n',
    ],
)
def test_detector_flags_timing_unsafe_forms(source: str) -> None:
    """Guard: the walker must see the mutations it exists to catch."""
    assert _secret_equality_compares(ast.parse(source))


@pytest.mark.parametrize(
    "source",
    [
        "if not token or not hmac.compare_digest(token.encode(), expected.encode()):\n    pass\n",
        "if stored_otp is None:\n    pass\n",
        'if token == "":\n    pass\n',
    ],
)
def test_detector_allows_safe_forms(source: str) -> None:
    assert _secret_equality_compares(ast.parse(source)) == []


async def test_bearer_verifier_calls_compare_digest() -> None:
    from scoped_mcp.http_auth import BearerTokenVerifier

    verifier = BearerTokenVerifier(expected_token="placeholder-token", agent_id="dev")
    with patch("scoped_mcp.http_auth.hmac.compare_digest", wraps=hmac.compare_digest) as spy:
        assert await verifier.verify_token("placeholder-token") is not None
        assert await verifier.verify_token("wrong-token-xx") is None
    assert spy.call_count == 2


def test_hitl_endpoint_bearer_calls_compare_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    from scoped_mcp import hitl_http

    monkeypatch.setenv(hitl_http._HITL_TOKEN_ENV, "placeholder-hitl-token")
    good = type("Req", (), {"headers": {"authorization": "Bearer placeholder-hitl-token"}})()
    bad = type("Req", (), {"headers": {"authorization": "Bearer wrong-token-xxxxxxxx"}})()
    with patch("scoped_mcp.hitl_http.hmac.compare_digest", wraps=hmac.compare_digest) as spy:
        assert hitl_http._check_bearer(good)[0] is True
        assert hitl_http._check_bearer(bad) == (False, 401)
    assert spy.call_count == 2
