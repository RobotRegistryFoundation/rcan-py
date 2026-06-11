# Adding RCAN Validation to Your CI

## GitHub Actions

```yaml
- name: Validate RCAN configs
  uses: RobotRegistryFoundation/rcan-py/.github/actions/validate-rcan@main
  with:
    level: "2"
```

Full workflow `.github/workflows/rcan-validate.yml`:

```yaml
name: Validate RCAN
on: [push, pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: RobotRegistryFoundation/rcan-py/.github/actions/validate-rcan@main
        with:
          level: "1"
```

## Pre-commit hooks

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/RobotRegistryFoundation/rcan-py
    rev: v0.1.0
    hooks:
      - id: rcan-validate-config
      - id: rcan-validate-message
      - id: rcan-validate-audit
```

```bash
pip install pre-commit && pre-commit install
```

## CLI

```bash
rcan-validate config myrobot.rcan.yaml [--level 2] [--json]
rcan-validate message command.json
rcan-validate audit .opencastor-commitments.jsonl
rcan-validate uri 'rcan://registry.rcan.dev/acme/arm/v2/unit-001'
```

## Exit codes: 0 = pass, 1 = fail, 2 = warnings (with --strict)
