# Contributing to NetGuard

Thank you for your interest in contributing. This guide covers everything you
need to get a working development environment, understand the coding standards,
and submit a pull request.

---

## Table of Contents

1. [Development Setup](#development-setup)
2. [Project Structure](#project-structure)
3. [Coding Standards](#coding-standards)
4. [Writing Tests](#writing-tests)
5. [Pull Request Process](#pull-request-process)
6. [Adding a Detection Rule](#adding-a-detection-rule)

---

## Development Setup

### Requirements

- Python 3.11+
- Linux recommended (iptables required for prevention tests)
- Git

### Steps

```bash
# 1. Fork and clone
git clone https://github.com/<your-fork>/midvalleyproject.git
cd midvalleyproject

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Initialise the database
python -c "from database.init_db import initialize_db; initialize_db()"

# 5. Copy environment config
cp .env.example .env

# 6. Run the test suite to verify setup
pytest --tb=short
```

### Running in development mode

```bash
# No root needed for development (iptables calls will fail gracefully)
python backend/main.py
```

The app starts at `http://localhost:5000`. The iptables privilege check is
non-fatal in development — a WARNING is logged and monitoring continues without
blocking capability.

---

## Project Structure

See [README.md](README.md#directory-structure) for the full directory layout.

Key patterns:

- **Services** live in `backend/services/` and are injected via the dependency
  registry in `backend/api/dependencies.py`. Route blueprints call
  `get_<service>()` — never import services directly.
- **Detection rules** all inherit from `BaseRule` in
  `detection/rules/base_rule.py`. Each rule is one file, one class.
- **Routes** are thin — validate input, call the service, return the envelope.
  Business logic belongs in services.
- **Repositories** in `backend/repositories/` contain all SQLAlchemy queries.
  Services never write SQL directly.

---

## Coding Standards

### Style

- Follow [PEP 8](https://peps.python.org/pep-0008/).
- Use type hints on all public function signatures (`from __future__ import annotations`).
- Prefer `f-strings` over `.format()`.
- Maximum line length: 100 characters.
- Use `from __future__ import annotations` at the top of every module.

### Docstrings

Every public module, class, and function must have a Google-style docstring:

```python
def block_ip(self, ip: str, reason: str, event_id: str) -> bool:
    """
    Block an IP address via iptables and record the block in the database.

    Args:
        ip: IPv4 or IPv6 address to block.
        reason: Attack type that triggered the block.
        event_id: Originating ThreatEvent ID.

    Returns:
        True if block was applied (new or extended), False on failure.

    Raises:
        ValueError: If ip is not a valid address string.
    """
```

Module-level docstrings must include: purpose, responsibilities, dependencies, usage example.

### Error handling

- Services must never raise to route handlers unless documented in the function signature.
- Use specific exception types (`ValueError`, `RuntimeError`) with descriptive messages.
- Catch broad `Exception` only at integration boundaries; log with `exc_info=True`.
- Routes return HTTP 422 for validation errors, 404 for not found, 500 for unexpected failures.

### Security

- Always validate IP addresses with `require_valid_ip()` before passing to iptables or the DB.
- Never log passwords, tokens, secrets, or private keys (see `_SENSITIVE_KEYS` in `log_service.py`).
- Use `shlex.quote()` on any IP string passed to subprocess commands.

---

## Writing Tests

All tests live in `tests/`. The suite uses pytest + Hypothesis.

### Test categories

| Category | Location | Description |
|----------|----------|-------------|
| Unit | `tests/test_*.py` | Single class or function, no I/O |
| Property-based | `tests/test_*.py` (with `@given`) | Hypothesis strategies |
| Integration | `tests/integration/` | Full API flow with Flask test client |

### Running tests

```bash
# All tests
pytest

# With coverage
pytest --cov=backend --cov=detection --cov=database --cov-report=term-missing

# One file
pytest tests/test_detection_service.py -v

# Only fast tests
pytest tests/ -k "not integration" --tb=short
```

### Requirements

- New detection rules must have tests for: `process_packet()`, `evaluate()`,
  severity tiers, confidence formula, `explain()` output.
- New API endpoints must have an integration test covering: happy path, missing
  fields, invalid IP, and service unavailable (service is `None`).
- New configuration settings must have a property-based test covering the valid
  range boundaries.
- All new code must keep the coverage at or above the existing baseline.

### Property-based test example

```python
from hypothesis import given, strategies as st

@given(st.integers(min_value=100, max_value=199))
def test_syn_severity_medium(count):
    assert _syn_severity(count) == "Medium"

@given(st.integers(min_value=400))
def test_syn_severity_critical(count):
    assert _syn_severity(count) == "Critical"
```

---

## Pull Request Process

1. **Branch** from `main` using the format `feature/<description>` or
   `fix/<description>`.
2. **Write tests** for any new code before or alongside the implementation.
3. **Run the full test suite** locally and confirm it passes.
4. **Update documentation**: if you change a public API, update the relevant
   docstring, README section, and docs/ file.
5. **Open the PR** against `main`. Fill in the PR template:
   - Summary of what changed and why
   - What was tested
   - Any known limitations or follow-up work
6. PRs require at least one review and a green test run before merge.

### Commit message format

```
type: short imperative summary (≤70 chars)

Optional body explaining why, not what.
Reference issues as: Closes #123
```

Types: `feat` · `fix` · `docs` · `refactor` · `test` · `chore`

---

## Adding a Detection Rule

1. Create `detection/rules/<name>.py` with a class that inherits `BaseRule`.
2. Set `rule_name = "RULE_ID_001"` and `attack_type = "Attack Name"` as class attributes.
3. Implement all six abstract methods: `initialize`, `process_packet`, `evaluate`,
   `generate_event`, `explain`, `cleanup`.
4. Register the rule in `DetectionEngine._build_rules()` in
   `backend/services/detection_service.py`.
5. Add the rule toggle to `config/config.yaml` under `rules_enabled`.
6. Add default seed data to `database/init_db.py` in `_DEFAULT_RULES`.
7. Write tests covering all public methods and severity/confidence edge cases.
