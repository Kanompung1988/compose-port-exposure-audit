---
name: compose-port-exposure-audit
description: Use when you need to review Docker Compose published host port mappings and host networking before deployment, pinpointing unintended public interfaces and exposed data-service ports. Trigger for a Docker Compose YAML change introduces ports, a database container is published, or a review needs evidence of bind-address decisions; do not use for live deployment proof or cluster access.
license: MIT
compatibility: Python 3.10+; install PyYAML>=6,<7; local filesystem read only.
---

# Compose Port Exposure Audit

Use this skill to help an agent review a local config change without guessing about runtime reachability. Read [references/MODEL.md](references/MODEL.md) for source-backed semantics and limitations.

## When to use

- A docker compose yaml change introduces ports, a database container is published, or a review needs evidence of bind-address decisions.
- Need a reproducible review artifact from local files to attach to a pull request.

## Do not use

- You need a live firewall/network scan, a docker daemon policy audit, image vulnerability scanning, secret inspection, or a guarantee of internet reachability.
- Do not infer operational exposure or broken deploys without running the platform-native tool in the actual target environment.

## Procedure

1. Confirm the repository location and ask for only the minimum local configuration file/chart path (do not request secret values).
2. Install the declared Python dependency: `python -m pip install -r requirements.txt`.
3. Run `python scripts/audit.py compose.yaml --format text --fail-on high` from the skill repository. To avoid CI hard failures while reviewing, add `--fail-on never`.
4. Record actual `code`, `severity`, `file`/`path` and source line where present. Do not conflate `INFO` or `REVIEW` with a confirmed vulnerability.
5. For each finding, explain the precise static evidence, a narrow remediation suggestion, and what runtime check is still needed.
6. Validate any proposed change with the official Docker Compose or Helm CLI (outside this skill), plus unit/fixture tests. Never make code changes without user approval.
7. If input is malformed (exit code 2), stop instead of presenting incomplete results as clean.

## Command and exit codes

```
python scripts/audit.py examples/review.yaml --format json --fail-on never
python -m unittest discover -s tests -v
```

`0`: no configured failure threshold reached; `1`: a finding at the selected threshold; `2`: invalid/unreadable input. Exit 0 is not a proof of security.

## Safety and limits

This is a static Compose-file heuristic, not Docker runtime introspection. Daemon defaults, firewalls, host routes, container listeners, Compose interpolation, modes and per-host policies can change actual reachability. It does not parse multiple Compose overrides, network ranges or nonstandard mappings; it explicitly reports unresolved cases for review.

Outputs are static, deterministic and do not contact Docker, Kubernetes, Helm repositories, or network endpoints.
