from __future__ import annotations

import json
import unittest

from ghost_audit.engine import ALLOWED_PAIRS, STEP_KEYS


class ContractTests(unittest.TestCase):
    def test_only_documented_phase_operation_state_pairs_are_allowed(self) -> None:
        self.assertEqual(len(ALLOWED_PAIRS), 15)
        self.assertTrue(all(phase in {"FINDING", "REMEDIATION", "VERIFICATION"}
                            for phase, _, _ in ALLOWED_PAIRS))

    def test_required_step_schema_is_exact(self) -> None:
        sample = {"step_no": 1, "phase": "FINDING", "system_id": "search_service",
                  "resource_id": "search_demo_1", "operation": "REPORT_REMAINING_RECORD",
                  "state": "PRESENT", "evidence_id": "demo_evidence"}
        self.assertEqual(set(sample), STEP_KEYS)
        self.assertIsInstance(json.loads(json.dumps([sample])), list)
