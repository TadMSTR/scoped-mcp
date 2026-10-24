"""Secrets are compared in constant time (vikunja#1219, same class as vikunja#759).

A behavioural test cannot see timing, so an ``==`` / ``!=`` that replaced
``hmac.compare_digest`` would pass every functional test. Two structural checks:

- every function known to compare a secret must still call ``compare_digest``, and every
  ``compare_digest`` call in ``src/`` (``hmac.compare_digest`` or a bare imported name) must
  belong to a known function, so a new site is registered here rather than silently unpinned;
- no ``==`` / ``!=`` / ``in`` / ``not in`` in ``src/`` has an operand whose name looks like a
  secret, except presence checks (against ``None``, ``""`` or ``b""``) and the reviewed
  non-secret compares in ``_NOT_SECRETS``.

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

from scoped_mcp import __file__ as _PKG_INIT

_PKG = Path(_PKG_INIT).parent

# (file relative to the package, function) for every secret compare in src/.
_CONSTANT_TIME_SITES = {
    ("http_auth.py", "verify_token"),  # per-agent HTTP bearer
    ("hitl_http.py", "_check_bearer"),  # /hitl/* endpoint bearer
    ("hitl_endpoint.py", "approve"),  # Phase 2 courier OTP
}

_SECRET_NAME = re.compile(
    r"token|secret|passw|signature|(^|_)sig($|_)|otp|presented|expected|digest|hmac"
    r"|(^|_)mac($|_)|bearer",
    re.IGNORECASE,
)


# Compares whose operand names match _SECRET_NAME but hold no secret. Keyed on
# (file, function, matched names), so another compare in the same file or function on a
# differently named operand is still caught. Each entry must still match a compare.
_NOT_SECRETS = {
    # A boolean health flag, not a token.
    ("credentials_vault.py", "_renew_once", "token_healthy"): "renewal health edge detection",
    # SHA-256 of the approval's arguments, which the approver already holds: integrity, not
    # secrecy, so there is no value for a timing side channel to recover.
    ("hitl.py", "_short_args_hash", "digest"): "args digest vs the unhashable sentinel",
    ("hitl_approver.py", "check_record", "digest"): "stored vs recomputed args digest",
}


def _sources() -> dict[str, ast.AST]:
    return {str(p.relative_to(_PKG)): ast.parse(p.read_text()) for p in sorted(_PKG.rglob("*.py"))}


def _calls_compare_digest(node: ast.AST) -> bool:
    """``hmac.compare_digest(...)`` or a bare ``compare_digest(...)`` imported by name."""
    return any(
        isinstance(n, ast.Call)
        and (
            (isinstance(n.func, ast.Attribute) and n.func.attr == "compare_digest")
            or (isinstance(n.func, ast.Name) and n.func.id == "compare_digest")
        )
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
        elif (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Attribute)
            and sub.func.attr == "get"
            and sub.args
            and isinstance(sub.args[0], ast.Constant)
            and isinstance(sub.args[0].value, str)
        ):
            out.add(sub.args[0].value)  # headers.get("x-hitl-token")
    return out


def _is_presence_check(node: ast.AST) -> bool:
    """Comparisons against None or "" are presence checks and carry no secret timing."""
    return isinstance(node, ast.Constant) and node.value in (None, "", b"")


_VALUE_OPS = (ast.Eq, ast.NotEq, ast.In, ast.NotIn)


def _enclosing_function(tree: ast.AST) -> dict[ast.AST, str]:
    """Map every node to the name of its innermost enclosing function ("" at module level)."""
    owner: dict[ast.AST, str] = {}

    def visit(node: ast.AST, name: str) -> None:
        for child in ast.iter_child_nodes(node):
            inner = (
                child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else name
            )
            owner[child] = inner
            visit(child, inner)

    visit(tree, "")
    return owner


def _secret_equality_compares(tree: ast.AST) -> list[tuple[int, str, str]]:
    """(line, enclosing function, matched names) for each value compare on a secret name."""
    owner = _enclosing_function(tree)
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        if not any(isinstance(op, _VALUE_OPS) for op in node.ops):
            continue
        operands = [node.left, *node.comparators]
        if any(_is_presence_check(o) for o in operands):
            continue
        hits = {n for o in operands for n in _names(o) if _SECRET_NAME.search(n)}
        if hits:
            found.append((node.lineno, owner.get(node, ""), ", ".join(sorted(hits))))
    return found


@pytest.mark.parametrize(("filename", "function"), sorted(_CONSTANT_TIME_SITES))
def test_known_secret_compares_still_use_compare_digest(filename: str, function: str) -> None:
    tree = _sources()[filename]
    matches = [f for f in _functions(tree) if f.name == function]
    assert matches, f"{filename}:{function} not found; update _CONSTANT_TIME_SITES"
    assert any(_calls_compare_digest(f) for f in matches), (
        f"{filename}:{function} no longer calls compare_digest"
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
                (line, function, names)
                for line, function, names in _secret_equality_compares(tree)
                if (filename, function, names) not in _NOT_SECRETS
            ]
        )
    }
    assert found == {}, f"use hmac.compare_digest, not ==/!=/in: {found}"


def test_every_not_secret_exemption_still_matches() -> None:
    """A stale exemption fails, so the list cannot quietly accumulate entries."""
    seen = {
        (filename, function, names)
        for filename, tree in _sources().items()
        for _line, function, names in _secret_equality_compares(tree)
    }
    assert set(_NOT_SECRETS) <= seen, set(_NOT_SECRETS) - seen


@pytest.mark.parametrize(
    "source",
    [
        "if not token or token.encode() != self._expected_token.encode():\n    pass\n",
        "if not presented or presented != expected:\n    pass\n",
        "if stored_otp is None or otp != stored_otp:\n    pass\n",
        "ok = sig == expected_sig\n",
        'ok = token == "fixed-secret"\n',
        "if otp not in (stored_otp,):\n    pass\n",
        "ok = token in allowed\n",
        'ok = request.headers.get("x-hitl-token") == header\n',
        "ok = stored_mac != computed\n",
        "ok = hmac_sig == other\n",
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


@pytest.mark.parametrize(
    "source",
    [
        "def f(a, b):\n    return hmac.compare_digest(a, b)\n",
        "from hmac import compare_digest\ndef f(a, b):\n    return compare_digest(a, b)\n",
    ],
)
def test_compare_digest_is_seen_in_both_import_forms(source: str) -> None:
    """Guard: a bare imported compare_digest must count as a site, or it escapes the registry."""
    assert _calls_compare_digest(ast.parse(source))


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
