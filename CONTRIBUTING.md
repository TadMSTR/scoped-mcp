# Contributing

## How to add a module

1. Create `src/scoped_mcp/modules/<name>.py`
   - Subclass `ToolModule` from `_base.py`
   - Declare `name`, `scoping`, and `required_credentials`
   - Mark tools with `@tool(mode="read")` or `@tool(mode="write")`
   - Notification modules (write-only) use neither mode — just `@tool(mode="write")`

2. Add tests in `tests/test_modules/test_<name>.py`
   - Every module must have tests for:
     - Normal operation (happy path, at minimum one read and one write if applicable)
     - Scope enforcement: verify out-of-scope access is blocked
     - Cross-agent isolation: Agent A cannot access Agent B's resources
     - Credential isolation: credential values must not appear in module config or tool responses
   - For `PrefixScope` modules: include traversal attack tests (`../`, symlinks, absolute paths)
   - For modules that accept SQL: include PRAGMA/ATTACH/multi-statement tests

3. Add an example manifest entry in `examples/manifests/`

4. Update the module table in `README.md`

## Testing requirements

```bash
# Run all tests
pytest

# Run scoping tests (most critical)
pytest tests/test_scoping.py

# Run a specific module's tests
pytest tests/test_modules/test_<name>.py

# Run with coverage
pytest --cov=scoped_mcp --cov-report=term-missing
```

Coverage threshold: 80% overall, 100% on `scoping.py` and `exceptions.py`.

All tests must pass before opening a PR. CI runs the full matrix (Python 3.11–3.14).

## Code style

```bash
# Lint
ruff check src/ tests/

# Format
ruff format src/ tests/
```

Line length: 100 characters. Target: Python 3.11+.

## Comment policy

Comments exist to prevent agents from breaking security invariants, not to explain what the code does.

Write a comment when:
- You're enforcing a security boundary and the reason isn't obvious from the code
- You're documenting an invariant that must not be changed (e.g., "enforce() MUST be called before any backend operation")
- You're explaining why a simpler-looking alternative is wrong

Do not write comments that restate what the code does (`# loop over items`).

## What not to change without discussion

- The `ToolModule` base class interface in `_base.py`
- The manifest schema (breaking changes affect every user's config)
- The audit log field names and structure (downstream consumers depend on them)
- The `ScopeStrategy` interface in `scoping.py`

Changes to these require a major version bump (v1.0.0+) and a migration guide.

## PR process

1. Fork and create a feature branch (`git checkout -b feat/my-module`)
2. Write tests first (TDD is encouraged)
3. Implement the feature
4. Run `pytest` and `ruff check`
5. Open a PR against `main`
6. CI must pass before merge
