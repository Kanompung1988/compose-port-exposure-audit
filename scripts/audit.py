#!/usr/bin/env python3
"""Read-only Docker Compose published-port exposure review (static heuristics)."""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

MAX_BYTES = 1024 * 1024
# Human-readable, low-risk examples of data services, not proof of vulnerabilities.
DATA_PORTS = {5432: "PostgreSQL", 3306: "MySQL", 6379: "Redis", 27017: "MongoDB",
              9200: "Elasticsearch", 11211: "Memcached", 5672: "AMQP", 15672: "AMQP UI"}
LOOPBACK = {"127.0.0.1", "::1"}
BIND_ALL = {"", "0.0.0.0", "::", "[::]"}
INTERPOLATION = re.compile(r"\$\{|\$[A-Za-z_]")


class InvalidCompose(ValueError):
    """Input is malformed/unsupported and cannot be safely analyzed."""


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def _mapping(loader: yaml.Loader, node: yaml.nodes.MappingNode) -> dict:
    loader.flatten_mapping(node)
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, (str, int, float, bool, tuple)):
            raise InvalidCompose("unsupported YAML mapping key")
        if key in result:
            raise InvalidCompose("duplicate YAML mapping key")
        result[key] = loader.construct_object(value_node, deep=True)
    return result


UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    service: str
    path: str
    detail: str
    recommendation: str


def _finding(code: str, severity: str, service: str, path: str, detail: str, fix: str) -> Finding:
    return Finding(code, severity, service, path, detail, fix)


def _port_int(port: Any) -> int | None:
    if isinstance(port, bool) or port is None:
        return None
    if isinstance(port, int):
        return port if 1 <= port <= 65535 else None
    text = str(port).strip()
    if not text.isdecimal():
        return None
    value = int(text)
    return value if 1 <= value <= 65535 else None


def _short_port(value: Any) -> tuple[str, str, str, str] | None:
    """Return (host_ip, published, target, protocol); no interpolation guesses."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return None
    spec = str(value).strip()
    if not spec or INTERPOLATION.search(spec):
        return None
    if spec.startswith("["):
        end = spec.find("]")
        if end < 0 or spec[end + 1:end + 2] != ":":
            return None
        ip = spec[1:end]
        rest = spec[end + 2:]
        fields = rest.split(":")
        if len(fields) != 2:
            return None
        published, target = fields
    else:
        fields = spec.split(":")
        if len(fields) == 1:
            ip, published, target = "", "", fields[0]
        elif len(fields) == 2:
            ip, published, target = "", fields[0], fields[1]
        elif len(fields) == 3:
            ip, published, target = fields
        else:
            return None
    target_parts = target.split("/", 1)
    protocol = target_parts[1].lower() if len(target_parts) == 2 else "tcp"
    return ip, published, target_parts[0], protocol


def _long_port(value: dict) -> tuple[str, str, str, str] | None:
    # A long-form mapping may include fields not relevant to host publication.
    if not isinstance(value, dict):
        return None
    ip = value.get("host_ip", "")
    target = value.get("target")
    published = value.get("published", "")
    protocol = value.get("protocol", "tcp")
    if not isinstance(ip, str) or not isinstance(protocol, str):
        return None
    if target is None or any(INTERPOLATION.search(str(v)) for v in (ip, target, published, protocol)):
        return None
    return ip, str(published), str(target), protocol.lower()


def audit(data: Any) -> list[Finding]:
    if not isinstance(data, dict):
        raise InvalidCompose("Compose document must be a YAML mapping")
    services = data.get("services")
    if not isinstance(services, dict):
        raise InvalidCompose("services must be a mapping")
    findings: list[Finding] = []
    for name, cfg in sorted(services.items(), key=lambda kv: str(kv[0])):
        if not isinstance(name, str) or not isinstance(cfg, dict):
            raise InvalidCompose("each service must be named and mapped")
        if cfg.get("network_mode") == "host":
            findings.append(_finding("HOST_NETWORK", "MEDIUM", name, f"services.{name}.network_mode",
                "Host networking bypasses Compose port publishing and deserves manual exposure review.",
                "Verify application listen addresses and host firewall; prefer an isolated bridge when possible."))
        ports = cfg.get("ports", [])
        if ports is None:
            ports = []
        if not isinstance(ports, list):
            raise InvalidCompose(f"services.{name}.ports must be a list")
        for i, raw in enumerate(ports):
            path = f"services.{name}.ports[{i}]"
            parsed = _long_port(raw) if isinstance(raw, dict) else _short_port(raw)
            if parsed is None:
                findings.append(_finding("UNRESOLVED_PORT", "INFO", name, path,
                    "Cannot determine bind address statically (unsupported form, range or variable).",
                    "Inspect the fully resolved Compose config and host network settings manually."))
                continue
            ip, published, target, protocol = parsed
            port = _port_int(target)
            if port is None or (published and _port_int(published) is None):
                findings.append(_finding("UNRESOLVED_PORT", "INFO", name, path,
                    "Port range, invalid value or dynamic port could not be classified.",
                    "Inspect resolved published port mapping before production use."))
                continue
            if ip in LOOPBACK:
                continue
            if ip in BIND_ALL:
                if port in DATA_PORTS:
                    findings.append(_finding("DATA_PORT_PUBLIC_BIND", "HIGH", name, path,
                        f"{DATA_PORTS[port]} container port {port}/{protocol} is published without a loopback bind.",
                        "Bind to 127.0.0.1/[::1] or remove published mapping; enforce auth and firewall."))
                else:
                    findings.append(_finding("PUBLIC_BIND", "MEDIUM", name, path,
                        f"Container port {port}/{protocol} is published on default/all host interfaces.",
                        "Confirm intended external access, authentication, firewall and daemon default bind."))
            else:
                findings.append(_finding("INTERFACE_BIND", "INFO", name, path,
                    f"Published mapping binds to explicit non-loopback interface {ip}.",
                    "Confirm interface reachability and firewall rules; this does not prove Internet exposure."))
    return findings


def load(path: Path) -> Any:
    try:
        if not path.is_file():
            raise InvalidCompose("input must be an existing regular file")
        if path.stat().st_size > MAX_BYTES:
            raise InvalidCompose("input exceeds 1 MiB limit")
        text = path.read_text(encoding="utf-8")
        return yaml.load(text, Loader=UniqueKeyLoader)
    except (OSError, UnicodeError, yaml.YAMLError, RecursionError) as exc:
        raise InvalidCompose(f"cannot read valid Compose YAML: {type(exc).__name__}") from exc


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("compose", type=Path, help="Path to a local Compose YAML")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--fail-on", choices=("never", "high", "medium"), default="high")
    args = parser.parse_args(argv)
    try:
        findings = audit(load(args.compose))
    except InvalidCompose as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps({"findings": [asdict(x) for x in findings], "counts": {
            level: sum(x.severity == level for x in findings) for level in ("HIGH", "MEDIUM", "INFO")}}, indent=2))
    else:
        for item in findings:
            print(f"[{item.severity}] {item.code} {item.path}: {item.detail}\n  Next: {item.recommendation}")
        print(f"Findings: {len(findings)} (static review; not a network scan)")
    threshold = {"never": set(), "high": {"HIGH"}, "medium": {"HIGH", "MEDIUM"}}[args.fail_on]
    return 1 if any(f.severity in threshold for f in findings) else 0


if __name__ == "__main__":
    sys.exit(run())
