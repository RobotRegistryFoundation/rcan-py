# CLAUDE.md — rcan-py Development Guide

> **Agent context file.** Read this before making any changes.

## What Is rcan-py?

`rcan-py` is the official Python SDK for the RCAN robot communication protocol. It provides:
- `RobotURI` — parse, build, and validate `rcan://` URIs
- `RegistryClient` — async/sync CRUD for rcan.dev API (register, get, list, search, patch)
- `rcan-validate` CLI — validate config files and live robot records against the canonical JSON schema
- `RCANMessage`, `NodeClient`, message type constants

**Version**: 0.8.0 | **Spec**: see [rcan.dev/compatibility](https://rcan.dev/compatibility) | **Python**: 3.10+ | **Tests**: 609 passing

## Repository Layout

```
rcan-py/
├── rcan/
│   ├── __init__.py         # __version__, SPEC_VERSION, public exports
│   ├── version.py          # SPEC_VERSION, SDK_VERSION — single source of truth (always sync with rcan-spec)
│   ├── message.py          # RCANMessage dataclass, SPEC_VERSION, MessageType constants
│   ├── uri.py              # RobotURI — parse/validate rcan:// URIs
│   ├── registry.py         # RegistryClient — async HTTP client for rcan.dev API
│   ├── validate.py         # rcan-validate CLI + config/schema validation
│   ├── node.py             # NodeClient — connect to a running RCAN node
│   └── exceptions.py       # RCANError, RCANNotFoundError, RCANAuthError, ...
├── tests/
│   ├── test_version.py     # SPEC_VERSION and __version__ assertions
│   ├── test_registry.py    # RegistryClient tests (mocked HTTP)
│   ├── test_uri.py         # RobotURI parsing tests
│   └── ...
├── pyproject.toml          # name = "rcan", version = "3.4.0"
└── CHANGELOG.md
```

## Key Constants

```python
import rcan

rcan.__version__       # "3.4.0"
rcan.SPEC_VERSION      # "3.2"  — tracks current stable spec version
rcan.__spec_version__  # "3.2"  — alias
```

SPEC_VERSION is defined in `rcan/version.py` — always keep in sync with `rcan-spec` `package.json` version field. Both `__init__.py` and `message.py` re-export it.

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -q              # 589 tests, should all pass
pytest tests/test_version.py  # Checks SPEC_VERSION assertions specifically
```

## SPEC_VERSION Bump Protocol

When the RCAN spec releases a new stable version:
1. Update `rcan/__init__.py`: `__spec_version__`, `SPEC_VERSION`
2. Update `rcan/message.py`: `SPEC_VERSION`
3. Update `pyproject.toml`: `version` (minor bump, e.g. 0.3.x → 0.4.0)
4. Update `rcan/__init__.py`: `__version__`
5. Update `tests/test_version.py`: assertions for new version strings
6. Update `CHANGELOG.md`: add new entry at top
7. Run `pytest tests/ -q` to confirm all passing
8. Commit and push

## RegistryClient

```python
from rcan.registry import RegistryClient

async with RegistryClient() as client:
    # Register a robot
    result = await client.register(
        manufacturer="craigm26",
        model="opencastor-rpi5-hailo",
        version="v2026.3.13.11",
        device_id="bob-rpi5-hailo-0001",
        metadata={"category": "robot", "capabilities": ["nav", "vision"]},
    )
    print(result["rrn"])  # RRN-000000000001

    # Look up by RRN
    robot = await client.get_robot("RRN-000000000001")
```

Default base URL: `https://rcan.dev` (from `DEFAULT_BASE_URL`).

## ValidationResult (rcan ≥ 0.3.0)

`validate_config()` returns a `ValidationResult` object (not a tuple). Check with `hasattr(result, 'ok')`:

```python
result = validate_config(config)
if hasattr(result, 'ok'):
    valid, errors = result.ok, result.issues
else:
    valid, errors = result  # legacy tuple
```

OpenCastor's `castor/rcan/sdk_compat.py` handles this compatibility layer.

## Code Style

- Type hints on all public functions
- Async-first for IO operations; sync wrappers (`_run_sync()`) for convenience
- Exceptions: raise from `rcan.exceptions` hierarchy, not raw `Exception`
- No dependencies beyond stdlib + `httpx` (optional) — keep it lightweight

## Security Notes

- **encode_minimal()** now accepts `shared_secret` parameter; using `msg_id` as HMAC key is deprecated (2026-03-19)

## v1.7–v1.8 Additions (2026-03-20)

- **v1.8 Canonical MessageType table**: 36 types with fixed integers — verified by `tests/test_canonical_types.py`
- **MessageType**: `CONTRIBUTE_REQUEST` (33), `CONTRIBUTE_RESULT` (34), `CONTRIBUTE_CANCEL` (35), `TRAINING_DATA` (36)
- **Scope validation**: `contribute` scope mapped to chat-level LoA in `identity._SCOPE_FIELD_MAP`
- **Transport**: `encode_compact()` / `decode_compact()` for RCAN-over-MQTT; `encode_minimal()` for ESTOP frames
- **Compatibility**: OpenCastor ≥2026.3.21.1
