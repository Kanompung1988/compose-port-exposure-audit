"""Regression tests for published-port parsing and fail-safe behavior."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("compose_audit", HERE / "scripts" / "audit.py")
mod = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)


class ComposeTests(unittest.TestCase):
    def review(self, ports, extra=None):
        cfg = {"ports": ports}
        if extra:
            cfg.update(extra)
        return mod.audit({"services": {"db": cfg}})

    def test_public_postgres(self):
        self.assertEqual(self.review(["5432:5432"])[0].code, "DATA_PORT_PUBLIC_BIND")

    def test_public_redis(self):
        self.assertEqual(self.review(["6379:6379"])[0].severity, "HIGH")

    def test_public_mongo(self):
        self.assertEqual(self.review(["27017:27017"])[0].severity, "HIGH")

    def test_public_mysql(self):
        self.assertEqual(self.review(["3306:3306"])[0].severity, "HIGH")

    def test_public_general(self):
        self.assertEqual(self.review(["8080:80"])[0].severity, "MEDIUM")

    def test_localhost_accepted(self):
        self.assertEqual(self.review(["127.0.0.1:8080:80"]), [])

    def test_ipv6_localhost_accepted(self):
        self.assertEqual(self.review(["[::1]:8080:80"]), [])

    def test_ipv6_any(self):
        self.assertEqual(self.review(["[::]:8080:80"])[0].code, "PUBLIC_BIND")

    def test_explicit_any(self):
        self.assertEqual(self.review(["0.0.0.0:8080:80"])[0].code, "PUBLIC_BIND")

    def test_protocol_udp(self):
        self.assertIn("udp", self.review(["53:53/udp"])[0].detail)

    def test_single_port_ephemeral(self):
        self.assertEqual(self.review(["80"])[0].code, "PUBLIC_BIND")

    def test_integer_ephemeral(self):
        self.assertEqual(self.review([80])[0].code, "PUBLIC_BIND")

    def test_long_mapping(self):
        self.assertEqual(self.review([{"target": 5432, "published": "15432"}])[0].severity, "HIGH")

    def test_long_loopback(self):
        self.assertEqual(self.review([{"target": 5432, "published": 15432, "host_ip": "127.0.0.1"}]), [])

    def test_long_ipv6(self):
        self.assertEqual(self.review([{"target": 443, "published": 8443, "host_ip": "::"}])[0].code, "PUBLIC_BIND")

    def test_external_interface_is_info(self):
        self.assertEqual(self.review(["192.168.1.20:8080:80"])[0].severity, "INFO")

    def test_interpolation_unknown(self):
        self.assertEqual(self.review(["${PORT:-8080}:80"])[0].code, "UNRESOLVED_PORT")

    def test_port_ranges_unknown(self):
        self.assertEqual(self.review(["8000-8010:80-90"])[0].code, "UNRESOLVED_PORT")

    def test_invalid_short_unknown(self):
        self.assertEqual(self.review(["abc:80"])[0].code, "UNRESOLVED_PORT")

    def test_bad_bool_unknown(self):
        self.assertEqual(self.review([True])[0].code, "UNRESOLVED_PORT")

    def test_missing_services(self):
        with self.assertRaises(mod.InvalidCompose):
            mod.audit({})

    def test_nonlist_ports(self):
        with self.assertRaises(mod.InvalidCompose):
            mod.audit({"services": {"x": {"ports": "80:80"}}})

    def test_empty_service(self):
        self.assertEqual(mod.audit({"services": {"app": {}}}), [])

    def test_host_network(self):
        self.assertEqual(mod.audit({"services": {"x": {"network_mode": "host"}}})[0].code, "HOST_NETWORK")

    def test_duplicate_yaml_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            file = Path(d) / "compose.yaml"
            file.write_text("services:\n  x: {}\nservices:\n  y: {}\n")
            with self.assertRaises(mod.InvalidCompose):
                mod.load(file)

    def test_bad_yaml_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            file = Path(d) / "compose.yaml"
            file.write_text("services: [\n")
            with self.assertRaises(mod.InvalidCompose):
                mod.load(file)

    def test_large_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            file = Path(d) / "compose.yaml"
            file.write_bytes(b"x" * (mod.MAX_BYTES + 1))
            with self.assertRaises(mod.InvalidCompose):
                mod.load(file)

    def test_safe_cli(self):
        result = subprocess.run([sys.executable, str(HERE / "scripts/audit.py"),
            str(HERE / "examples/safe.yaml")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_review_cli_json(self):
        result = subprocess.run([sys.executable, str(HERE / "scripts/audit.py"),
            str(HERE / "examples/review.yaml"), "--format", "json"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertGreater(json.loads(result.stdout)["counts"]["HIGH"], 0)

    def test_fail_on_never(self):
        result = subprocess.run([sys.executable, str(HERE / "scripts/audit.py"),
            str(HERE / "examples/review.yaml"), "--fail-on", "never"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
