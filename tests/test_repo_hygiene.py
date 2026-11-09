"""Repository hygiene that a code change can silently undo.

.gitignore once had a bare ``core.*`` for core dumps. That also matches a legitimate module
called ``core.py``, which would then never be committed and would vanish from the next
clone without any error. The rule is ``core.[0-9]*`` (the numeric core-dump suffix).
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]


def _ignored(path: str) -> bool:
    # --no-index: judge the path against the rules alone, whether or not it exists or is
    # tracked. Exit 0 = ignored, 1 = not ignored, anything else = git failed.
    proc = subprocess.run(
        ["git", "-C", str(REPO), "check-ignore", "-q", "--no-index", path],
        capture_output=True,
        check=False,
    )
    if proc.returncode not in (0, 1):
        pytest.skip(f"git check-ignore failed: {proc.stderr.decode(errors='replace')}")
    return proc.returncode == 0


@pytest.fixture(autouse=True)
def _needs_a_git_checkout() -> None:
    if shutil.which("git") is None or not (REPO / ".git").exists():
        pytest.skip("not a git checkout (sdist or installed copy)")


@pytest.mark.parametrize("path", ["src/scoped_mcp/core.py", "core.py", "tests/core.yaml"])
def test_files_named_core_are_not_ignored(path: str) -> None:
    assert not _ignored(path)


@pytest.mark.parametrize("path", ["core.1234", "src/core.98765", "crash.core"])
def test_core_dumps_are_still_ignored(path: str) -> None:
    """The control: the narrowed rule still catches real core dumps."""
    assert _ignored(path)
