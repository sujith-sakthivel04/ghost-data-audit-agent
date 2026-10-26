from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from ghost_audit.cli import main as cli_main
from ghost_audit.engine import run_audit
from ghost_audit.models import AuditConfig

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEMO = PROJECT_ROOT / "examples" / "synthetic" / "bundle"


class EngineSmokeTests(unittest.TestCase):
    def test_synthetic_bundle_runs_and_obeys_status_contract(self) -> None:
        with tempfile.TemporaryDirectory(dir=PROJECT_ROOT) as temporary:
            output = Path(temporary) / "demo.csv"
            summary = run_audit(AuditConfig(DEMO / "requests.csv", DEMO, output))
            self.assertEqual(summary.request_count, 2)
            self.assertEqual(summary.status_counts, {"INCOMPLETE": 1, "NOT_APPLICABLE": 1})
            with output.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual([r["case_id"] for r in rows], ["demo_case_001", "demo_case_002"])
            incomplete = json.loads(rows[0]["steps_json"])
            self.assertTrue(any(s["operation"] == "REPORT_REMAINING_RECORD" for s in incomplete))
            self.assertTrue(any(s["operation"] == "REPORT_ACTIVE_DATA_FLOW" for s in incomplete))
            self.assertTrue(any(s["operation"] == "REDACT_RECORD" for s in incomplete))
            self.assertEqual(json.loads(rows[1]["steps_json"]), [])

    def test_cli_run_and_validate_commands(self) -> None:
        with tempfile.TemporaryDirectory(dir=PROJECT_ROOT) as temporary:
            output = Path(temporary) / "cli.csv"
            result = cli_main(["run", "--requests", str(DEMO / "requests.csv"),
                               "--evidence-dir", str(DEMO / "evidence"), "--output", str(output)])
            self.assertEqual(result, 0)
            self.assertEqual(cli_main(["validate", "--requests", str(DEMO / "requests.csv"),
                                       "--output", str(output)]), 0)
