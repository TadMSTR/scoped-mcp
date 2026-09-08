#!/usr/bin/env bash
#
# Verify a built distribution before it is trusted.
#
# ONE DEFINITION, TWO CALL SITES: ci.yml runs it on every PR, release.yml runs it between
# `build` and `publish-pypi`. That second call is the point of the script. Before this existed
# release.yml went build -> upload artifact -> download artifact -> publish, with nothing in
# between asserting anything at all about what was being pushed to PyPI. Flagship requires the
# publish path to run the same check as the PR path, before pushing rather than after.
#
# WHAT THIS REPLACES. ci.yml previously had a step named "Verify wheel contents" that did:
#
#     pip install dist/*.whl
#     python -c "import scoped_mcp; print(...)"
#
# That is an install smoke test. It asserts the wheel is installable and importable; it asserts
# nothing whatsoever about contents. The name read as covered in review and was not. The
# install smoke is kept below — it is a useful check — but it is now one assertion among
# several rather than the whole of a step claiming to verify contents.
#
# Usage:  verify-dist.sh [DIST_DIR] [EXPECTED_VERSION]
#
#   DIST_DIR          defaults to ./dist
#   EXPECTED_VERSION  optional. When set (release.yml passes the tag with the leading `v`
#                     stripped) the artefact filenames must carry exactly this version. This is
#                     the assertion that catches publishing something other than what the tag
#                     names — a real risk in release.yml specifically, because the job that
#                     publishes is not the job that built, and it trusts a downloaded artifact.
set -euo pipefail

DIST_DIR="${1:-dist}"
EXPECTED_VERSION="${2:-}"

fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "  ok: $*"; }

[ -d "$DIST_DIR" ] || fail "no such directory: $DIST_DIR"

echo "== verify-dist: $DIST_DIR =="

# --------------------------------------------------------------------------
# 1. Exactly one wheel and one sdist.
#
# More than one means a stale build is sitting in the directory, and `pip install dist/*.whl`
# or twine's glob would pick one nondeterministically. Zero means the build silently produced
# nothing, which a `set -e` on `python -m build` does not always catch.
# --------------------------------------------------------------------------
shopt -s nullglob
wheels=("$DIST_DIR"/*.whl)
sdists=("$DIST_DIR"/*.tar.gz)
shopt -u nullglob

[ "${#wheels[@]}" -eq 1 ] || fail "expected exactly 1 wheel in $DIST_DIR, found ${#wheels[@]}: ${wheels[*]:-none}"
[ "${#sdists[@]}" -eq 1 ] || fail "expected exactly 1 sdist in $DIST_DIR, found ${#sdists[@]}: ${sdists[*]:-none}"
WHEEL="${wheels[0]}"
SDIST="${sdists[0]}"
ok "one wheel ($(basename "$WHEEL")) and one sdist ($(basename "$SDIST"))"

# --------------------------------------------------------------------------
# 2. Version agreement.
#
# pyproject is the source of truth. The wheel and sdist filenames must agree with it, and with
# EXPECTED_VERSION when the caller supplies one.
# --------------------------------------------------------------------------
PYPROJECT_VERSION="$(python3 -c '
import re, sys, pathlib
text = pathlib.Path("pyproject.toml").read_text(encoding="utf-8")
m = re.search(r"^version\s*=\s*\"([^\"]+)\"", text, re.M)
if not m:
    sys.exit("could not read version from pyproject.toml")
print(m.group(1))
')"

WHEEL_VERSION="$(basename "$WHEEL" | awk -F- '{print $2}')"
SDIST_VERSION="$(basename "$SDIST" | sed -E 's/^scoped_mcp-(.+)\.tar\.gz$/\1/')"

[ "$WHEEL_VERSION" = "$PYPROJECT_VERSION" ] \
  || fail "wheel version $WHEEL_VERSION != pyproject version $PYPROJECT_VERSION"
[ "$SDIST_VERSION" = "$PYPROJECT_VERSION" ] \
  || fail "sdist version $SDIST_VERSION != pyproject version $PYPROJECT_VERSION"
ok "wheel, sdist and pyproject all say $PYPROJECT_VERSION"

if [ -n "$EXPECTED_VERSION" ]; then
  [ "$PYPROJECT_VERSION" = "$EXPECTED_VERSION" ] \
    || fail "tag says $EXPECTED_VERSION but the artefact is $PYPROJECT_VERSION — refusing to publish"
  ok "artefact version matches the tag ($EXPECTED_VERSION)"
fi

# --------------------------------------------------------------------------
# 3. Wheel top-level layout.
#
# A wheel for this project should contain exactly two top-level entries: the package and its
# dist-info. Anything else is build context that escaped into the artefact — the usual culprits
# being a stray `tests/` from a misconfigured `packages =`, or a top-level module shadowing
# something in site-packages.
# --------------------------------------------------------------------------
mapfile -t top_level < <(unzip -Z1 "$WHEEL" | awk -F/ 'NF>1 {print $1}' | sort -u)
expected_dist_info="scoped_mcp-${PYPROJECT_VERSION}.dist-info"
for entry in "${top_level[@]}"; do
  case "$entry" in
    scoped_mcp|"$expected_dist_info") ;;
    *) fail "unexpected top-level entry in wheel: $entry (expected only scoped_mcp/ and $expected_dist_info/)" ;;
  esac
done
[ "${#top_level[@]}" -eq 2 ] || fail "wheel has ${#top_level[@]} top-level entries, expected 2: ${top_level[*]}"
ok "wheel top level is exactly scoped_mcp/ and $expected_dist_info/"

# --------------------------------------------------------------------------
# 4. Nothing that should never ship, in EITHER artefact.
#
# The wheel and the sdist are both uploaded to PyPI, so both are published surface. The sdist
# legitimately carries tests/, docs/ and examples/ — that is what an sdist is for — so the
# directory checks below apply to the wheel only, while the secret-pattern check applies to
# both. Splitting them matters: a blanket rule over the sdist would either have to permit
# everything (and catch nothing) or reject a correct sdist.
# --------------------------------------------------------------------------
wheel_manifest="$(unzip -Z1 "$WHEEL")"
for forbidden in tests/ test/ docs/ examples/ migrations/ .github/ .venv/; do
  if grep -qE "(^|/)${forbidden//./\\.}" <<<"$wheel_manifest"; then
    fail "wheel ships $forbidden — build context escaped into the artefact"
  fi
done
ok "wheel ships no tests/, docs/, examples/, migrations/, .github/ or .venv/"

# Secret-shaped filenames. This is a backstop, not the primary control — .gitignore and
# gitleaks are — but it is the last gate before an upload that cannot be taken back. PyPI does
# not allow deleting and re-uploading a filename, so a secret published here is published
# permanently.
sdist_manifest="$(tar tzf "$SDIST")"
secret_hits="$(printf '%s\n%s\n' "$wheel_manifest" "$sdist_manifest" \
  | grep -EI '(^|/)(\.env($|\..*)|.*\.(key|pem|p12|pfx)|secrets?\.(ya?ml|json|toml)|id_(rsa|ed25519)|.*\.kdbx)$' || true)"
if [ -n "$secret_hits" ]; then
  # Deliberately does NOT echo the matched paths' contents — only the paths, which are already
  # in the manifest. vikunja#606: keep exploitable detail out of CI logs on a public repo.
  fail "secret-shaped file(s) in a published artefact:"$'\n'"$secret_hits"
fi
ok "no secret-shaped filenames in either artefact"

# --------------------------------------------------------------------------
# 5. The package is actually in there.
#
# An assertion that things are ABSENT passes trivially against an empty artefact. This is the
# paired positive: the contract a consumer depends on must be present. Without it, a build that
# produced a wheel containing nothing but dist-info would sail through every check above.
# --------------------------------------------------------------------------
for required in \
  "scoped_mcp/__init__.py" \
  "scoped_mcp/server.py" \
  "scoped_mcp/scoping.py" \
  "scoped_mcp/manifest.py" \
  "${expected_dist_info}/METADATA" \
  "${expected_dist_info}/entry_points.txt" \
  "${expected_dist_info}/licenses/LICENSE"
do
  grep -qxF "$required" <<<"$wheel_manifest" || fail "wheel is missing $required"
done
ok "wheel carries the package, its metadata, the entry point and the licence"

module_count="$(grep -cE '^scoped_mcp/modules/.+\.py$' <<<"$wheel_manifest" || true)"
[ "$module_count" -ge 10 ] \
  || fail "wheel carries only $module_count files under scoped_mcp/modules/ — expected at least 10"
ok "wheel carries $module_count module files"

# The console script is the documented way to run this. A wheel that installs but exposes no
# entry point is broken in a way `import scoped_mcp` cannot detect.
unzip -p "$WHEEL" "${expected_dist_info}/entry_points.txt" | grep -q '^scoped-mcp *=' \
  || fail "entry_points.txt does not declare the scoped-mcp console script"
ok "entry_points.txt declares the scoped-mcp console script"

# --------------------------------------------------------------------------
# 6. Install smoke — kept from the old step, now one assertion among several.
#
# Into a throwaway venv rather than the job's environment: installing into the ambient
# environment means the subsequent `import` can succeed against the source tree or an
# already-installed copy rather than against the wheel under test.
# --------------------------------------------------------------------------
VENV_DIR="$(mktemp -d)"
trap 'rm -rf "$VENV_DIR"' EXIT
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --quiet --disable-pip-version-check "$WHEEL"

installed_version="$("$VENV_DIR/bin/python" -c 'import scoped_mcp; print(scoped_mcp.__version__)')"
[ "$installed_version" = "$PYPROJECT_VERSION" ] \
  || fail "installed package reports $installed_version, artefact claims $PYPROJECT_VERSION"
ok "installs into a clean venv and reports $installed_version"

# --------------------------------------------------------------------------
# 7. The installed console script parses this project's core input format.
#
# `scoped-mcp validate --manifest ...` is the `--check` config validation Flagship asks for,
# and pointing it at examples/manifests/ closes a second gap in the same step: those seven
# example directories were referenced by no workflow at all. An example nothing exercises rots
# — searxng-mcp's compose examples are the cited case — and a manifest that no longer parses is
# a broken example of the one format every consumer of this package has to write.
#
# Run from the INSTALLED wheel, not the source tree, so this is a statement about the artefact
# rather than about the repository. The manifests are read from the checkout; release.yml's
# verify job checks out the repo for exactly this reason.
# --------------------------------------------------------------------------
MANIFEST_DIR="${MANIFEST_DIR:-examples/manifests}"
if [ -d "$MANIFEST_DIR" ]; then
  shopt -s nullglob
  manifests=("$MANIFEST_DIR"/*.yml "$MANIFEST_DIR"/*.yaml)
  shopt -u nullglob
  [ "${#manifests[@]}" -gt 0 ] || fail "$MANIFEST_DIR contains no manifests to validate"
  for manifest in "${manifests[@]}"; do
    "$VENV_DIR/bin/scoped-mcp" validate --manifest "$manifest" >/dev/null \
      || fail "the installed wheel cannot validate $manifest"
  done
  ok "installed wheel validates all ${#manifests[@]} manifests in $MANIFEST_DIR"
else
  fail "$MANIFEST_DIR not found — the examples must be present to be exercised"
fi

# --------------------------------------------------------------------------
# 8. The artefact enforces the boundary it exists to enforce.
#
# The unit suite covers scoping thoroughly, but it runs against src/. This runs against the
# INSTALLED WHEEL, which is what an external party actually gets, and asserts the one property
# that would make shipping this package actively harmful if it were wrong.
#
# BOTH DIRECTIONS, AND THE ACCEPT CASE IS NOT OPTIONAL. Part 2 of this programme demonstrated
# the failure mode rather than arguing it: a build with verification patched to reject
# everything passed both of its refusal assertions, and only the accept case caught it. An
# enforce() that raised unconditionally would satisfy every refusal below and be completely
# broken — it would deny every legitimate call in production. A refusal-only smoke test cannot
# tell a working boundary from a brick.
# --------------------------------------------------------------------------
SCOPE_ROOT="$(mktemp -d)"
trap 'rm -rf "$VENV_DIR" "$SCOPE_ROOT"' EXIT

SCOPE_ROOT="$SCOPE_ROOT" "$VENV_DIR/bin/python" - <<'PY' || fail "the installed wheel does not enforce the scoping contract"
import os, sys
from scoped_mcp.scoping import PrefixScope
from scoped_mcp.identity import AgentContext
from scoped_mcp.exceptions import ScopeViolation

scope = PrefixScope(os.environ["SCOPE_ROOT"])
agent_a = AgentContext(agent_id="agent-a", agent_type="build")

problems = []

# ACCEPT — an in-scope path must be permitted. This is the control.
#
# enforce() validates an already-scoped path, which is what a module holds after calling
# apply(); it is not a relative-path validator. Feeding it a bare "notes.md" makes every
# assertion below pass for the wrong reason, since a relative path resolves against the process
# cwd and is correctly refused. The pairing with apply() is the real call sequence.
for good in ("notes.md", "sub/dir/file.txt"):
    scoped = scope.apply(good, agent_a)
    try:
        scope.enforce(scoped, agent_a)
    except ScopeViolation as exc:
        problems.append(f"refused an IN-SCOPE path {scoped!r}: {exc}")

# REFUSE — each of these escapes agent-a's root and must raise.
for bad in (
    "../../etc/passwd",          # traversal out of the base entirely
    "../agent-b/secret",         # traversal into another agent's root
    "/etc/passwd",               # absolute path outside the base
    "sub/../../agent-b/secret",  # traversal that only escapes after normalisation
):
    try:
        scope.enforce(bad, agent_a)
    except ScopeViolation:
        pass
    else:
        problems.append(f"PERMITTED an out-of-scope path {bad!r}")

# Two agents must not share a root — the isolation this package is named for.
agent_b = AgentContext(agent_id="agent-b", agent_type="build")
if scope.apply("notes.md", agent_a) == scope.apply("notes.md", agent_b):
    problems.append("two different agents resolve the same name to the same path")

if problems:
    for p in problems:
        print(f"    scoping contract: {p}", file=sys.stderr)
    sys.exit(1)
print("    scoping contract: 2 in-scope accepted, 4 out-of-scope refused, agents isolated")
PY
ok "the installed wheel enforces the scoping contract in both directions"

echo "== verify-dist: PASS =="
