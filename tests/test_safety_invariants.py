"""Isolated regression tests for evidence retrieval and deletion audits.

Run from the product root with:
    python -m unittest discover -s tests -v

All fixtures are synthetic and created under a temporary directory. No challenge
case IDs, output labels, or participant dataset records are used here.
"""
from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
from ghost_audit import engine as agent  # noqa: E402


UTC = timezone.utc
CAPTURE = "2026-01-10T10:00:00Z"
AUDIT = "2026-01-10T12:00:00Z"
ALICE = "alice@example.invalid"
BOB = "alicia@example.invalid"


class SyntheticDataset:
    """Small participant-shaped dataset; all values are test-only fiction."""

    def __init__(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix=".test-ghost-audit-",
                                                 dir=PROJECT_ROOT)
        self.root = Path(self.temp.name)
        (self.root / "evidence").mkdir()
        self.manifest: list[dict[str, str]] = []
        self.activities: list[dict[str, str]] = []
        self.identity_audits: list[dict[str, str]] = []
        self.identities = [
            {"user_id": "user_100", "name": "Avery Example", "email": ALICE,
             "phone": "+1-555-0101", "email_hash": "a" * 64, "updated_at": CAPTURE},
            {"user_id": "user_200", "name": "Alex Example", "email": BOB,
             "phone": "+1-555-0202", "email_hash": "b" * 64, "updated_at": CAPTURE},
        ]
        self.requests: list[dict[str, str]] = []

    def close(self) -> None:
        self.temp.cleanup()

    def write_csv(self, name: str, rows: list[dict[str, str]], fields: tuple[str, ...] | None = None) -> None:
        path = self.root / name
        if fields is None:
            fields = tuple(rows[0]) if rows else ()
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)

    def add_evidence(self, file_id: str, rel: str, body: str | bytes,
                     captured_at: str = CAPTURE) -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(body, bytes):
            path.write_bytes(body)
        else:
            path.write_text(body, encoding="utf-8")
        self.manifest.append({"file_id": file_id, "file_path": rel, "captured_at": captured_at})
        return path

    def add_request(self, case_id: str, email: str = ALICE, audit_at: str = AUDIT,
                    request_text: str = "Please delete my account and all personal data.",
                    reported_status: str = "COMPLETE") -> dict[str, str]:
        row = {"case_id": case_id, "email": email, "requested_at": "2026-01-10T09:00:00Z",
               "reported_status": reported_status, "reported_at": "2026-01-10T11:00:00Z",
               "audit_at": audit_at, "request_text": request_text}
        self.requests.append(row)
        return row

    def add_identity_history(self, uid: str = "user_100", old: str = "old.alice@example.invalid",
                             new: str = ALICE, event_time: str = "2025-12-01T00:00:00Z") -> None:
        self.identity_audits.append({"audit_id": "audit_synthetic_1", "user_id": uid,
                                     "field_name": "email", "old_value": old,
                                     "new_value": new, "event_time": event_time})

    def add_activity(self, activity_id: str, resource_id: str, event_type: str,
                     details: str, event_time: str = "2026-01-10T10:30:00Z",
                     result: str = "SUCCESS") -> None:
        self.activities.append({"activity_id": activity_id, "event_time": event_time,
                                "event_type": event_type, "source_system": "synthetic_worker",
                                "target_system": agent.infer_system(resource_id),
                                "resource_id": resource_id, "reported_result": result,
                                "details": details})

    def finalize(self) -> None:
        self.write_csv("evidence_files.csv", self.manifest,
                       ("file_id", "file_path", "captured_at"))
        self.write_csv("user_identities.csv", self.identities)
        self.write_csv("user_audit_log.csv", self.identity_audits,
                       ("audit_id", "user_id", "field_name", "old_value", "new_value", "event_time"))
        self.write_csv("system_activity.csv", self.activities,
                       ("activity_id", "event_time", "event_type", "source_system", "target_system",
                        "resource_id", "reported_result", "details"))
        self.write_csv("deletion_requests.csv", self.requests,
                       ("case_id", "email", "requested_at", "reported_status", "reported_at",
                        "audit_at", "request_text"))
        self.write_csv("deletion_rules.csv", [],
                       ("rule_id", "data_category", "condition", "required_action"))

    def run(self, request: dict[str, str]) -> tuple[dict[str, str], agent.EvidenceIndex]:
        self.finalize()
        maps = agent.build_identity_maps(self.root)
        activities = agent.load_activity(self.root)
        index = agent.EvidenceIndex(self.root)
        nearest = agent.assign_activity_nearest_case([request], activities)
        output = agent.build_case_output(request, [request], index, activities, maps, nearest)
        return output, index


def decode(output: dict[str, str]) -> list[dict[str, object]]:
    return json.loads(output["steps_json"])


def minimal_text_pdf(lines: list[str]) -> bytes:
    """Build a tiny valid Helvetica PDF without a test-only PDF authoring dependency."""
    commands = ["BT", "/F1 12 Tf", "72 720 Td"]
    for i, line in enumerate(lines):
        escaped = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        if i:
            commands.append("0 -20 Td")
        commands.append(f"({escaped}) Tj")
    commands.append("ET")
    stream = "\n".join(commands).encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, obj in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode("ascii"))
        output.extend(obj + b"\nendobj\n")
    xref_at = len(output)
    output.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n".encode("ascii"))
    return bytes(output)


class EvidenceAndStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = SyntheticDataset()

    def tearDown(self) -> None:
        self.data.close()

    def test_non_deletion_is_not_applicable_with_empty_steps(self) -> None:
        req = self.data.add_request("synthetic_1", request_text="Please update my phone number and leave the account active.")
        output, _ = self.data.run(req)
        self.assertEqual(output["deletion_status"], "NOT_APPLICABLE")
        self.assertEqual(decode(output), [])

    def test_historical_email_requires_supported_audit_alias(self) -> None:
        self.data.add_identity_history()
        old = "old.alice@example.invalid"
        self.data.add_evidence("evidence_old_email", "evidence/records/old.json",
                               json.dumps({"resource_id": "search_101", "email": old, "status": "PRESENT"}))
        historical_req = self.data.add_request("synthetic_2", email=old)
        historical_output, historical_index = self.data.run(historical_req)
        self.assertEqual(historical_index.diagnostics_by_case["synthetic_2"]["resolved_user_id"], "user_100")
        self.assertEqual(historical_output["deletion_status"], "INCOMPLETE")
        self.assertEqual(decode(historical_output)[0]["evidence_id"], "evidence_old_email")

        unknown = self.data.add_request("synthetic_3", email="old.alice2@example.invalid")
        unknown_output, unknown_index = self.data.run(unknown)
        self.assertEqual(unknown_index.diagnostics_by_case["synthetic_3"]["resolved_user_id"], "")
        self.assertNotIn("search_101", [c["resource_id"] for c in unknown_index.diagnostics_by_case["synthetic_3"]["candidates"]])
        self.assertEqual(decode(unknown_output), [])

    def test_audit_cutoff_is_inclusive_and_excludes_later_capture(self) -> None:
        cutoff = agent.parse_time(AUDIT)
        at_boundary = agent.Observation("evidence_boundary", "fixture", cutoff, cutoff,
                                        "search_102", "search_service", {}, "", "record", "PRESENT")
        one_tick_later = agent.Observation("evidence_late", "fixture", cutoff + timedelta(microseconds=1), cutoff,
                                           "search_103", "search_service", {}, "", "record", "PRESENT")
        self.assertTrue(agent.get_observation_cutoff(at_boundary, cutoff))
        self.assertFalse(agent.get_observation_cutoff(one_tick_later, cutoff))
        self.assertEqual(agent.parse_time("2026-01-10T17:30:00+05:30"), cutoff)
        self.assertIsNone(agent.parse_time("not-a-timestamp"))
        self.assertIsNone(agent.parse_time(""))

    def test_malformed_or_missing_manifest_capture_is_not_indexed(self) -> None:
        self.data.add_evidence("bad_time", "evidence/records/bad.json",
                               '{"resource_id":"search_104","email":"alice@example.invalid"}',
                               captured_at="not-a-timestamp")
        self.data.add_evidence("missing_time", "evidence/records/missing.json",
                               '{"resource_id":"search_105","email":"alice@example.invalid"}',
                               captured_at="")
        req = self.data.add_request("synthetic_4")
        _, index = self.data.run(req)
        self.assertFalse(any(o.file_id == "bad_time" for o in index.observations))
        self.assertFalse(any(o.file_id == "missing_time" for o in index.observations))

    def test_supported_formats_keep_source_provenance_and_find_exact_identity(self) -> None:
        self.data.add_evidence("e_csv", "evidence/records/rows.csv",
                               "resource_id,system_id,email,status,observed_at\nsearch_201,search_service,alice@example.invalid,PRESENT,2026-01-10T10:30:00Z\n")
        self.data.add_evidence("e_json", "evidence/records/rows.json",
                               json.dumps({"records": [{"resource_id": "support_202", "email": ALICE,
                                                        "message": "retained conversation"}]}))
        sql = """CREATE TABLE snapshot_scope(origin_system TEXT);
INSERT INTO snapshot_scope VALUES ('search_service');
CREATE TABLE records(resource_id TEXT, record_json TEXT, observed_at TEXT);
INSERT INTO records VALUES ('sessions_203', '{\"user_id\":\"user_100\",\"event\":\"checkout\"}', '2026-01-10T10:40:00Z');
"""
        self.data.add_evidence("e_sql", "evidence/databases/snapshot.sql", sql)
        self.data.add_evidence("e_log", "evidence/logs/trace.log",
                               "2026-01-10T10:45:00Z trace_id=trace-9 cache_204 email=alice@example.invalid status=PRESENT")
        self.data.add_evidence("e_text", "evidence/records/note.txt",
                               "2026-01-10T10:46:00Z export_205 email=alice@example.invalid status=PRESENT")

        self.data.add_evidence("e_pdf", "evidence/documents/attachment.pdf",
                               minimal_text_pdf(["support_206", "email=alice@example.invalid"]))

        from PIL import Image
        image_path = self.data.root / "evidence/images/screen.png"
        image_path.parent.mkdir(parents=True, exist_ok=True)
        Image.new("RGB", (400, 100), "white").save(image_path)
        self.data.manifest.append({"file_id": "e_image", "file_path": "evidence/images/screen.png",
                                   "captured_at": CAPTURE})
        with mock.patch.object(agent.EvidenceIndex, "_image_text",
                               return_value="marketing_207\nemail=alice@example.invalid\nstatus=PRESENT"):
            req = self.data.add_request("synthetic_5")
            _, index = self.data.run(req)

        by_file = {o.file_id for o in index.observations}
        for evidence_id in ("e_csv", "e_json", "e_sql", "e_log", "e_text", "e_pdf", "e_image"):
            self.assertIn(evidence_id, by_file, evidence_id)
        self.assertTrue(any(o.resource_id == "sessions_203" and o.fields.get("user_id") == "user_100"
                            and o.file_id == "e_sql" for o in index.observations))
        self.assertTrue(any(o.resource_id == "marketing_207" and o.file_id == "e_image"
                            and "alice@example.invalid" in o.raw_text for o in index.observations))

    def test_attributed_analytics_readback_survives_newer_weak_candidate(self) -> None:
        req = self.data.add_request("synthetic_analytics_rank_1")
        self.data.add_evidence("e_analytics_identity", "evidence/records/analytics_identity.json",
                               json.dumps({"resource_id": "analytics_901", "email": ALICE,
                                           "status": "PRESENT", "observed_at": "2026-01-10T10:10:00Z"}))
        self.data.add_evidence("e_analytics_readback", "evidence/records/analytics_readback.json",
                               json.dumps({"resource_id": "analytics_901", "email": None,
                                           "email_hash": None, "phone": None,
                                           "status": "ANONYMIZED", "observed_at": "2026-01-10T10:45:00Z"}))
        self.data.add_activity("activity_analytics_weak", "analytics_902", "ANONYMIZE_RECORD",
                               "Policy action completed for analytics_902.")
        self.data.add_evidence("e_analytics_weak_readback", "evidence/records/analytics_weak.json",
                               json.dumps({"resource_id": "analytics_902", "email": None,
                                           "email_hash": None, "phone": None,
                                           "status": "ANONYMIZED", "observed_at": "2026-01-10T10:55:00Z"}))
        output, index = self.data.run(req)
        steps = decode(output)
        self.assertIn("analytics_901", {s["resource_id"] for s in steps})
        self.assertNotIn("analytics_902", {s["resource_id"] for s in steps})
        self.assertTrue(any(s["resource_id"] == "analytics_901" and
                            s["operation"] == "VERIFY_RECORD_ANONYMIZED" and
                            s["evidence_id"] == "e_analytics_readback" for s in steps))

    def test_analytics_readback_with_conflicting_identity_is_rejected(self) -> None:
        req = self.data.add_request("synthetic_analytics_conflict")
        self.data.add_evidence("e_analytics_other_user", "evidence/records/analytics_other.json",
                               json.dumps({"resource_id": "analytics_903", "email": BOB,
                                           "status": "PRESENT"}))
        self.data.add_activity("activity_analytics_other_user", "analytics_903", "ANONYMIZE_RECORD",
                               "subject_reference=user_200 Policy action completed for analytics_903.")
        output, index = self.data.run(req)
        self.assertNotIn("analytics_903", {s["resource_id"] for s in decode(output)})
        self.assertNotIn("analytics_903", {c["resource_id"] for c in
                         index.diagnostics_by_case[req["case_id"]]["candidates"]})

    def test_anonymous_analytics_readback_without_subject_link_stays_ambiguous(self) -> None:
        req = self.data.add_request("synthetic_analytics_ambiguous")
        self.data.add_activity("activity_analytics_ambiguous", "analytics_904", "ANONYMIZE_RECORD",
                               "Policy action completed for analytics_904.")
        self.data.add_evidence("e_analytics_ambiguous", "evidence/records/analytics_ambiguous.json",
                               json.dumps({"resource_id": "analytics_904", "email": None,
                                           "email_hash": None, "phone": None,
                                           "status": "ANONYMIZED", "observed_at": "2026-01-10T10:40:00Z"}))
        output, index = self.data.run(req)
        self.assertEqual(output["deletion_status"], "INCOMPLETE")
        self.assertEqual(decode(output), [])
        self.assertNotIn("analytics_904", {s["resource_id"] for s in decode(output)})
        rejections = index.diagnostics_by_case[req["case_id"]]["ambiguous_candidates"]
        self.assertTrue(any(item.get("resource_id") == "analytics_904" and
                            "lacks a subject link" in item.get("reason", "") for item in rejections))

    def test_indirect_analytics_attribution_uses_cutoff_valid_resource_relationship(self) -> None:
        req = self.data.add_request("synthetic_analytics_indirect_link")
        self.data.add_evidence("e_subject_resource_map", "evidence/records/resource_map.json",
                               json.dumps({"resource_id": "support_912", "email": ALICE,
                                           "related_resource_id": "analytics_912", "status": "PRESENT"}))
        self.data.add_evidence("e_analytics_indirect_readback", "evidence/records/analytics_indirect.json",
                               json.dumps({"resource_id": "analytics_912", "email": None,
                                           "email_hash": None, "phone": None, "user_id": None,
                                           "status": "ANONYMIZED", "observed_at": "2026-01-10T10:40:00Z"}))
        output, index = self.data.run(req)
        self.assertTrue(any(s["resource_id"] == "analytics_912" and
                            s["operation"] == "VERIFY_RECORD_ANONYMIZED" for s in decode(output)))
        candidate = next(c for c in index.diagnostics_by_case[req["case_id"]]["candidates"]
                         if c["resource_id"] == "analytics_912")
        self.assertTrue(any("explicit resource link" in reason for reason in candidate["association_reasons"]))

    def test_rejecting_ambiguous_analytics_does_not_hide_supported_incomplete_finding(self) -> None:
        req = self.data.add_request("synthetic_analytics_ambiguous_with_finding")
        self.data.add_activity("activity_analytics_unlinked", "analytics_913", "ANONYMIZE_RECORD",
                               "Policy action completed for analytics_913.")
        self.data.add_evidence("e_analytics_unlinked", "evidence/records/analytics_unlinked.json",
                               json.dumps({"resource_id": "analytics_913", "email": None,
                                           "email_hash": None, "phone": None,
                                           "status": "ANONYMIZED", "observed_at": "2026-01-10T10:40:00Z"}))
        self.data.add_evidence("e_supported_search_record", "evidence/records/search_supported.json",
                               json.dumps({"resource_id": "search_914", "email": ALICE, "status": "PRESENT"}))
        output, _ = self.data.run(req)
        steps = decode(output)
        self.assertEqual(output["deletion_status"], "INCOMPLETE")
        self.assertTrue(steps)
        self.assertTrue(any(s["resource_id"] == "search_914" and
                            s["operation"] == "REPORT_REMAINING_RECORD" for s in steps))
        self.assertNotIn("analytics_913", {s["resource_id"] for s in steps})

    def test_late_analytics_capture_cannot_prove_earlier_anonymization(self) -> None:
        req = self.data.add_request("synthetic_late_analytics")
        self.data.add_activity("activity_analytics_direct_late", "analytics_905", "ANONYMIZE_RECORD",
                               "subject_reference=user_100 Policy action completed for analytics_905.")
        self.data.add_evidence("e_analytics_after_audit", "evidence/records/analytics_after.json",
                               json.dumps({"resource_id": "analytics_905", "email": None,
                                           "email_hash": None, "phone": None,
                                           "status": "ANONYMIZED", "observed_at": "2026-01-10T10:30:00Z"}),
                               captured_at="2026-01-10T12:00:00.000001Z")
        output, index = self.data.run(req)
        self.assertFalse(any(o.resource_id == "analytics_905" and
                             agent.get_observation_cutoff(o, agent.parse_time(req["audit_at"]))
                             for o in index.observations))
        self.assertNotIn("analytics_905", {s["resource_id"] for s in decode(output)})

    def test_two_attributed_analytics_resources_are_both_preserved(self) -> None:
        req = self.data.add_request("synthetic_two_analytics_resources")
        for rid, evidence_id in (("analytics_906", "e_analytics_a"), ("analytics_907", "e_analytics_b")):
            self.data.add_evidence(evidence_id, f"evidence/records/{rid}.json",
                                   json.dumps({"resource_id": rid, "email": ALICE,
                                               "status": "PRESENT", "observed_at": "2026-01-10T10:30:00Z"}))
        output, _ = self.data.run(req)
        steps = decode(output)
        self.assertEqual({s["resource_id"] for s in steps if s["phase"] == "FINDING"},
                         {"analytics_906", "analytics_907"})
        self.assertEqual({s["operation"] for s in steps if s["phase"] == "REMEDIATION"},
                         {"ANONYMIZE_RECORD"})

    def test_analytics_candidate_selection_is_independent_of_source_row_order(self) -> None:
        req = self.data.add_request("synthetic_analytics_order")
        for rid in ("analytics_908", "analytics_909"):
            self.data.add_evidence(f"e_{rid}", f"evidence/records/{rid}.json",
                                   json.dumps({"resource_id": rid, "email": ALICE, "status": "PRESENT",
                                               "observed_at": "2026-01-10T10:30:00Z"}))
        first, _ = self.data.run(req)
        self.data.manifest.reverse()
        second, _ = self.data.run(req)
        self.assertEqual(first, second)

    def test_phase6_account_activity_ambiguity_guard_is_unchanged(self) -> None:
        req_a = self.data.add_request("synthetic_phase6_account_a", reported_status="NOT_STARTED")
        req_b = {**req_a, "case_id": "synthetic_phase6_account_b",
                 "requested_at": "2026-01-10T09:01:00Z", "reported_at": "2026-01-10T11:01:00Z"}
        activity = agent.Activity("activity_phase6_account", agent.parse_time("2026-01-10T10:30:00Z"),
                                  "DELETE_RECORD", "worker", "account_service", "account_910", "FAILED",
                                  "submitted account_910")
        nearest = agent.assign_activity_nearest_case([req_a, req_b], [activity])
        self.assertEqual(nearest[activity.activity_id][0], "")
        for req in (req_a, req_b):
            selected = agent.infer_activity_candidates(req, [req_a, req_b], [activity], set(), set(), set(), "",
                                                       nearest)
            self.assertNotIn("account_910", selected)

    def test_explicit_analytics_subject_link_survives_candidate_filtering(self) -> None:
        req = self.data.add_request("synthetic_explicit_analytics_link")
        self.data.add_activity("activity_explicit_analytics", "analytics_911", "ANONYMIZE_RECORD",
                               "subject_reference=user_100 Policy action completed for analytics_911.")
        self.data.add_evidence("e_explicit_analytics_readback", "evidence/records/analytics_explicit.json",
                               json.dumps({"resource_id": "analytics_911", "email": None,
                                           "email_hash": None, "phone": None,
                                           "status": "ANONYMIZED", "observed_at": "2026-01-10T10:40:00Z"}))
        output, index = self.data.run(req)
        self.assertTrue(any(s["resource_id"] == "analytics_911" and
                            s["operation"] == "VERIFY_RECORD_ANONYMIZED" for s in decode(output)))
        self.assertIn("analytics_911", {c["resource_id"] for c in
                      index.diagnostics_by_case[req["case_id"]]["candidates"]})

    def test_missing_tesseract_fails_gracefully(self) -> None:
        from PIL import Image
        path = self.data.root / "unreadable.png"
        Image.new("RGB", (80, 40), "white").save(path)
        index = object.__new__(agent.EvidenceIndex)
        index._ocr_command_checked = False
        index._ocr_engine_checked = False
        index._ocr_engine_available = False
        index._ocr_command = ""
        with mock.patch.object(agent, "find_tesseract_executable", return_value=""):
            self.assertEqual(index._image_text(path), "")

    def test_local_ocr_cache_preserves_text_without_repeating_extraction(self) -> None:
        from PIL import Image
        import pytesseract
        path = self.data.root / "cached.png"
        Image.new("RGB", (100, 40), "white").save(path)
        index = object.__new__(agent.EvidenceIndex)
        index._ocr_command_checked = True
        index._ocr_engine_checked = True
        index._ocr_engine_available = True
        index._ocr_command = "local-test-tesseract"
        expected = "search_208 email=alice@example.invalid"
        with mock.patch.object(pytesseract, "image_to_string", return_value=expected) as extract:
            self.assertEqual(index._image_text(path), expected)
            self.assertEqual(index._image_text(path), expected)
            extract.assert_called_once()

    def test_local_screenshot_ocr_recovers_matching_identifier_when_available(self) -> None:
        from PIL import Image, ImageDraw, ImageFont
        executable = agent.find_tesseract_executable()
        if not executable:
            self.skipTest("local Tesseract is unavailable; graceful failure is covered separately")
        path = self.data.root / "evidence/images/readable.png"
        path.parent.mkdir(parents=True, exist_ok=True)
        image = Image.new("RGB", (1600, 500), "white")
        draw = ImageDraw.Draw(image)
        font = None
        for candidate in ("arial.ttf", "DejaVuSans.ttf"):
            try:
                font = ImageFont.truetype(candidate, 56)
                break
            except OSError:
                continue
        if font is None:
            self.skipTest("no suitable local font for a reproducible OCR screenshot")
        for index, line in enumerate(("resource_id: search_208",
                                      "email: alice@example.invalid",
                                      "status: PRESENT")):
            draw.text((40, 50 + index * 130), line, font=font, fill="black")
        image.save(path)
        self.data.manifest.append({"file_id": "e_screen", "file_path": "evidence/images/readable.png",
                                   "captured_at": CAPTURE})
        req = self.data.add_request("synthetic_16")
        self.data.finalize()
        index = agent.EvidenceIndex(self.data.root)
        found = [o for o in index.observations if o.file_id == "e_screen" and o.resource_id == "search_208"]
        self.assertTrue(found, "actual local OCR did not recover the resource ID")
        maps = agent.build_identity_maps(self.data.root)
        uid, aliases, normalized = agent.resolve_identity(req, maps, agent.parse_time(AUDIT))
        self.assertTrue(any(agent.obs_matches_user(o, aliases, normalized, uid) for o in found))

    def test_ambiguous_ocr_text_does_not_match_a_different_subject(self) -> None:
        self.data.add_evidence("e_ambiguous", "evidence/images/ambiguous.png", b"not-a-real-png")
        req = self.data.add_request("synthetic_6")
        with mock.patch.object(agent.EvidenceIndex, "_image_text",
                               return_value="search_301\nemail=alicia@example.invalid\nstatus=PRESENT"):
            output, index = self.data.run(req)
        self.assertFalse(any(o.resource_id == "search_301" and agent.obs_matches_user(
            o, {ALICE, "user_100"}, {agent.norm_text(ALICE), "user 100"}, "user_100")
            for o in index.observations))
        self.assertEqual(decode(output), [])

    def test_explicit_identity_wins_over_nearby_conflicting_activity(self) -> None:
        req = self.data.add_request("synthetic_7")
        matched = agent.Activity("activity_good", agent.parse_time("2026-01-10T10:30:00Z"),
                                 "DELETE_RECORD", "worker", "account_service", "account_401", "FAILED",
                                 "subject_reference=user_100")
        conflicting = agent.Activity("activity_nearby", agent.parse_time("2026-01-10T10:31:00Z"),
                                     "DELETE_RECORD", "worker", "account_service", "account_402", "SUCCESS",
                                     "subject_reference=user_200")
        nearest = {matched.activity_id: (req["case_id"], 0.1),
                   conflicting.activity_id: (req["case_id"], 0.2)}
        selected = agent.infer_activity_candidates(req, [req], [matched, conflicting], set(),
                                                   {"user_100", ALICE}, {"user 100", ALICE},
                                                   "user_100", nearest)
        self.assertEqual(set(selected), {"account_401"})

    def test_unique_weak_account_activity_is_still_discovered(self) -> None:
        req = self.data.add_request("synthetic_weak_unique", reported_status="NOT_STARTED")
        activity = agent.Activity("activity_unique", agent.parse_time("2026-01-10T10:30:00Z"),
                                  "DELETE_RECORD", "worker", "account_service", "account_811", "FAILED",
                                  "submitted account_811")
        nearest = agent.assign_activity_nearest_case([req], [activity])
        selected = agent.infer_activity_candidates(
            req, [req], [activity], set(), {ALICE}, {agent.norm_text(ALICE)}, "user_100", nearest
        )
        self.assertEqual(set(selected), {"account_811"})

    def test_explicit_account_link_survives_nearby_ambiguous_activities(self) -> None:
        req = self.data.add_request("synthetic_explicit_account", reported_status="NOT_STARTED")
        linked = agent.Activity("activity_linked_account", agent.parse_time("2026-01-10T10:30:00Z"),
                                "DELETE_RECORD", "worker", "account_service", "account_812", "FAILED",
                                "submitted account_812")
        weak_a = agent.Activity("activity_weak_a", agent.parse_time("2026-01-10T10:31:00Z"),
                                "DELETE_RECORD", "worker", "account_service", "account_813", "FAILED",
                                "submitted account_813")
        weak_b = agent.Activity("activity_weak_b", agent.parse_time("2026-01-10T10:32:00Z"),
                                "DELETE_RECORD", "worker", "account_service", "account_814", "FAILED",
                                "submitted account_814")
        nearest = {a.activity_id: (req["case_id"], 0.1) for a in (linked, weak_a, weak_b)}
        selected = agent.infer_activity_candidates(
            req, [req], [linked, weak_a, weak_b], {"account_812"}, set(), set(), "user_100", nearest
        )
        self.assertEqual(set(selected), {"account_812"})

    def test_two_similar_requests_leave_account_activity_ambiguous(self) -> None:
        req_a = self.data.add_request("synthetic_near_a", audit_at=AUDIT)
        req_b = {**req_a, "case_id": "synthetic_near_b", "requested_at": "2026-01-10T09:01:00Z",
                 "reported_at": "2026-01-10T11:01:00Z"}
        req_a["reported_status"] = req_b["reported_status"] = "NOT_STARTED"
        activity = agent.Activity("activity_ambiguous", agent.parse_time("2026-01-10T10:30:00Z"),
                                  "DELETE_RECORD", "worker", "account_service", "account_815", "FAILED",
                                  "submitted account_815")
        nearest = agent.assign_activity_nearest_case([req_a, req_b], [activity])
        self.assertEqual(nearest[activity.activity_id][0], "")
        for req in (req_a, req_b):
            selected = agent.infer_activity_candidates(
                req, [req_a, req_b], [activity], set(), set(), set(), "", nearest
            )
            self.assertNotIn("account_815", selected)

    def test_conflicting_activity_identity_blocks_weak_account_match(self) -> None:
        req = self.data.add_request("synthetic_activity_conflict", reported_status="NOT_STARTED")
        activity = agent.Activity("activity_conflicting_subject", agent.parse_time("2026-01-10T10:30:00Z"),
                                  "DELETE_RECORD", "worker", "account_service", "account_816", "FAILED",
                                  "subject_reference=user_200 submitted account_816")
        nearest = {activity.activity_id: (req["case_id"], 0.1)}
        selected = agent.infer_activity_candidates(
            req, [req], [activity], set(), {ALICE, "user_100"},
            {agent.norm_text(ALICE), "user 100"}, "user_100", nearest
        )
        self.assertEqual(selected, {})

    def test_preparsed_activity_identity_fields_preserve_conflict_results(self) -> None:
        details = "subject_reference=user_200 customer_email=alicia@example.invalid phone=+1-555-0202"
        timestamp = agent.parse_time("2026-01-10T10:30:00Z")
        parsed = agent.Activity("activity_cached", timestamp, "DELETE_RECORD", "worker",
                                "account_service", "account_819", "FAILED", details,
                                agent.parse_activity_identity_fields(details))
        fallback = agent.Activity("activity_fallback", timestamp, "DELETE_RECORD", "worker",
                                  "account_service", "account_819", "FAILED", details)
        self.assertEqual(parsed.identity_fields, {
            "subject_reference": ["user_200"],
            "customer_email": ["alicia@example.invalid"],
            "phone": ["+1-555-0202"],
        })
        for aliases, uid in (({ALICE, "user_100"}, "user_100"),
                             ({BOB, "user_200"}, "user_200")):
            self.assertEqual(agent.activity_conflicts_user(parsed, aliases, uid),
                             agent.activity_conflicts_user(fallback, aliases, uid))

    def test_indexed_candidate_retrieval_matches_scan_reference(self) -> None:
        alice = self.data.add_request("synthetic_index_alice", reported_status="NOT_STARTED")
        bob = {**alice, "case_id": "synthetic_index_bob", "email": BOB}
        unknown = {**alice, "case_id": "synthetic_index_empty", "email": "nobody@example.invalid"}
        requests = [alice, bob, unknown]
        old_email = "old.alice@example.invalid"
        self.data.add_identity_history(old=old_email)
        self.data.add_evidence(
            "e_index_old_alias", "evidence/records/index_old.json",
            json.dumps({"resource_id": "search_1201", "email": old_email, "status": "PRESENT",
                        "related_resource_id": "cache_1202", "observed_at": "2026-01-10T10:00:00Z"}),
        )
        self.data.add_evidence(
            "e_index_cache_alice", "evidence/records/index_cache_alice.json",
            json.dumps({"resource_id": "cache_1202", "email": ALICE, "status": "PRESENT"}),
        )
        self.data.add_evidence(
            "e_index_cache_bob", "evidence/records/index_cache_bob.json",
            json.dumps({"resource_id": "cache_1202", "email": BOB, "status": "ABSENT",
                        "observed_at": "2026-01-10T11:30:00Z"}),
        )
        self.data.add_evidence(
            "e_index_analytics_direct", "evidence/records/index_analytics_direct.json",
            json.dumps({"resource_id": "analytics_1203", "user_id": "user_100",
                        "status": "IDENTIFIABLE"}),
        )
        self.data.add_evidence(
            "e_index_analytics_indirect", "evidence/records/index_analytics_indirect.json",
            json.dumps({"resource_id": "analytics_1204", "email": ALICE,
                        "status": "IDENTIFIABLE"}),
        )
        self.data.add_activity("activity_index_catalog", "analytics_1204", "LINK_RESOURCE_IDENTITY",
                               "subject_reference=user_100 resource_id=analytics_1204",
                               event_time=AUDIT)
        self.data.add_activity("activity_index_pre_cutoff", "search_1205", "LINK_RESOURCE_IDENTITY",
                               "subject_reference=user_100", event_time="2026-01-10T11:59:59Z")
        self.data.add_activity("activity_index_after_cutoff", "search_1212", "LINK_RESOURCE_IDENTITY",
                               "subject_reference=user_100", event_time="2026-01-10T12:00:01Z")
        self.data.add_evidence(
            "e_index_before", "evidence/records/index_before.json",
            json.dumps({"resource_id": "search_1205", "email": ALICE, "status": "PRESENT"}),
        )
        self.data.add_evidence(
            "e_index_at_cutoff", "evidence/records/index_at_cutoff.json",
            json.dumps({"resource_id": "search_1206", "email": ALICE, "status": "ABSENT",
                        "observed_at": AUDIT}),
        )
        for file_id, rel in (("e_index_duplicate_one", "evidence/records/index_duplicate_one.json"),
                             ("e_index_duplicate_two", "evidence/records/index_duplicate_two.json")):
            self.data.add_evidence(file_id, rel, json.dumps({
                "resource_id": "search_1213", "email": ALICE, "status": "PRESENT",
                "observed_at": "2026-01-10T10:00:00Z",
            }))
        self.data.add_evidence(
            "e_index_contradictory", "evidence/records/index_contradictory.json",
            json.dumps({"resource_id": "search_1213", "email": ALICE, "status": "ABSENT",
                        "observed_at": "2026-01-10T11:30:00Z"}),
        )
        self.data.add_evidence(
            "e_index_after_cutoff", "evidence/records/index_after_cutoff.json",
            json.dumps({"resource_id": "search_1207", "email": ALICE, "status": "PRESENT",
                        "observed_at": "2026-01-10T12:00:01Z"}),
            captured_at="2026-01-10T12:00:01Z",
        )
        self.data.add_activity("activity_index_ambiguous_a", "account_1208", "DELETE_RECORD",
                               "submitted account_1208", result="FAILED")
        self.data.add_activity("activity_index_ambiguous_b", "account_1209", "DELETE_RECORD",
                               "submitted account_1209", result="FAILED")
        self.data.activities.append({"activity_id": "activity_index_malformed_time",
                                     "event_time": "not-a-time", "event_type": "LINK_RESOURCE_IDENTITY",
                                     "source_system": "synthetic", "target_system": "search_service",
                                     "resource_id": "search_1210", "reported_result": "SUCCESS",
                                     "details": "subject_reference=user_100"})
        malformed_path = self.data.add_evidence(
            "e_index_malformed_capture", "evidence/records/index_bad_capture.json",
            json.dumps({"resource_id": "search_1211", "email": ALICE, "status": "PRESENT"}),
        )
        self.data.manifest[-1]["captured_at"] = "bad-capture-time"
        self.data.finalize()
        maps = agent.build_identity_maps(self.data.root)
        activities = agent.load_activity(self.data.root)
        nearest = agent.assign_activity_nearest_case(requests, activities)
        self.assertEqual(nearest, agent.assign_activity_nearest_case(requests, activities, _scan_requests=True))
        activity_index = agent.ActivityRetrievalIndex(activities, nearest)

        def candidate_signature(candidates):
            return {
                rid: (
                    candidate.system_id, candidate.category, candidate.direct_match,
                    tuple(sorted((obs.file_id, obs.captured_at.isoformat(), obs.observed_at.isoformat(),
                                  obs.explicit_state, json.dumps(obs.fields, sort_keys=True, default=str))
                                 for obs in candidate.observations)),
                    tuple(sorted(activity.activity_id for activity in candidate.related_by_activity)),
                    tuple(sorted(candidate.association_reasons)),
                )
                for rid, candidate in sorted(candidates.items())
            }

        for request in requests:
            with self.subTest(case_id=request["case_id"]):
                audit_at = agent.parse_time(request["audit_at"])
                uid, aliases, normalized = agent.resolve_identity(request, maps, audit_at)
                index = agent.EvidenceIndex(self.data.root)
                indexed_matches = [
                    obs for obs in index.identity_candidates(aliases, normalized)
                    if agent.get_observation_cutoff(obs, audit_at)
                    and not agent.observation_conflicts_user(obs, aliases, normalized, uid)
                    and agent.obs_matches_user(obs, aliases, normalized, uid)
                ]
                scan_matches = [
                    obs for obs in index.observations
                    if agent.get_observation_cutoff(obs, audit_at)
                    and not agent.observation_conflicts_user(obs, aliases, normalized, uid)
                    and agent.obs_matches_user(obs, aliases, normalized, uid)
                ]
                self.assertEqual(
                    [(obs.file_id, obs.resource_id) for obs in indexed_matches],
                    [(obs.file_id, obs.resource_id) for obs in scan_matches],
                )
                indexed_result = agent.find_case_candidates(
                    request, requests, index, activities, maps, nearest, activity_index
                )
                scan_index = agent.EvidenceIndex(self.data.root)
                scan_result = agent.find_case_candidates(
                    request, requests, scan_index, activities, maps, nearest,
                    activity_index, _scan_retrieval=True,
                )
                self.assertEqual(indexed_result[0], scan_result[0])
                self.assertEqual(candidate_signature(indexed_result[1]), candidate_signature(scan_result[1]))

                indexed_output = agent.build_case_output(
                    request, requests, agent.EvidenceIndex(self.data.root), activities, maps, nearest,
                    activity_index,
                )
                scan_output = agent.build_case_output(
                    request, requests, agent.EvidenceIndex(self.data.root), activities, maps, nearest,
                    activity_index, _scan_retrieval=True,
                )
                self.assertEqual(indexed_output, scan_output)
        self.assertFalse(any(activity.activity_id == "activity_index_malformed_time" for activity in activities))
        self.assertIn("activity_index_after_cutoff", {activity.activity_id for activity in activities})
        self.assertFalse(any(obs.file_id == "e_index_malformed_capture" for obs in index.observations))

    def test_distinct_independently_attributed_account_resources_are_retained(self) -> None:
        req = self.data.add_request("synthetic_two_weak_accounts", reported_status="NOT_STARTED")
        other = {**req, "case_id": "synthetic_later_request", "requested_at": "2026-01-10T11:15:00Z",
                 "reported_at": "2026-01-10T13:15:00Z", "reported_status": "NOT_STARTED"}
        first = agent.Activity("activity_weak_unique_a", agent.parse_time("2026-01-10T10:30:00Z"),
                              "DELETE_RECORD", "worker", "account_service", "account_817", "FAILED",
                              "submitted account_817")
        second = agent.Activity("activity_weak_unique_b", agent.parse_time("2026-01-10T10:40:00Z"),
                               "DELETE_RECORD", "worker", "account_service", "account_818", "FAILED",
                               "submitted account_818")
        nearest = agent.assign_activity_nearest_case([req, other], [first, second])
        selected = agent.infer_activity_candidates(
            req, [req, other], [first, second], set(), {"user_100"}, {"user 100"}, "user_100", nearest
        )
        self.assertEqual(set(selected), {"account_817", "account_818"})

    def test_ambiguous_activity_assignment_is_independent_of_request_order(self) -> None:
        req_a = self.data.add_request("synthetic_order_a", audit_at=AUDIT)
        req_b = {**req_a, "case_id": "synthetic_order_b", "requested_at": "2026-01-10T09:01:00Z",
                 "reported_at": "2026-01-10T11:01:00Z", "reported_status": "NOT_STARTED"}
        req_a["reported_status"] = "NOT_STARTED"
        activity = agent.Activity("activity_order", agent.parse_time("2026-01-10T10:30:00Z"),
                                  "DELETE_RECORD", "worker", "account_service", "account_819", "FAILED",
                                  "submitted account_819")
        forward = agent.assign_activity_nearest_case([req_a, req_b], [activity])
        reverse = agent.assign_activity_nearest_case([req_b, req_a], [activity])
        self.assertEqual(forward, reverse)
        self.assertEqual(forward[activity.activity_id][0], "")

    def test_later_account_evidence_cannot_establish_cutoff_state(self) -> None:
        req = self.data.add_request("synthetic_late_account")
        self.data.add_evidence("e_account_after_audit", "evidence/records/account_late.json",
                               json.dumps({"resource_id": "account_820", "email": ALICE,
                                           "status": "PRESENT", "observed_at": "2026-01-10T10:30:00Z"}),
                               captured_at="2026-01-10T12:00:00.000001Z")
        self.data.add_activity("activity_late_account", "account_820", "DELETE_RECORD",
                               "submitted account_820", result="SUCCESS")
        output, index = self.data.run(req)
        self.assertFalse(any(o.resource_id == "account_820" and o.file_id == "e_account_after_audit"
                             and agent.get_observation_cutoff(o, agent.parse_time(req["audit_at"]))
                             for o in index.observations))
        self.assertEqual(output["deletion_status"], "INCOMPLETE")
        self.assertEqual(decode(output), [])

    def test_active_flow_remains_visible_when_account_candidates_are_ambiguous(self) -> None:
        req = self.data.add_request("synthetic_flow_with_account_ambiguity", reported_status="NOT_STARTED")
        competing = self.data.add_request("synthetic_flow_competing_request", email=BOB,
                                          reported_status="NOT_STARTED")
        self.data.add_evidence("e_active_flow", "evidence/records/active_flow.json",
                               json.dumps({"resource_id": "data_flow_821", "email": ALICE,
                                           "enabled": True, "status": "ACTIVE"}))
        self.data.add_activity("activity_flow_account_a", "account_822", "DELETE_RECORD",
                               "submitted account_822", result="FAILED")
        self.data.add_activity("activity_flow_account_b", "account_823", "DELETE_RECORD",
                               "submitted account_823", result="FAILED")
        self.data.finalize()
        maps = agent.build_identity_maps(self.data.root)
        activities = agent.load_activity(self.data.root)
        index = agent.EvidenceIndex(self.data.root)
        requests = [req, competing]
        nearest = agent.assign_activity_nearest_case(requests, activities)
        output = agent.build_case_output(req, requests, index, activities, maps, nearest)
        steps = decode(output)
        self.assertTrue(any(s["resource_id"] == "data_flow_821" and
                            s["operation"] == "REPORT_ACTIVE_DATA_FLOW" for s in steps))
        self.assertFalse(any(s["resource_id"] in {"account_822", "account_823"} for s in steps))

    def test_activity_and_observation_references_remain_attributable(self) -> None:
        req = self.data.add_request("synthetic_8")
        self.data.add_evidence("e_linked", "evidence/records/linked.json",
                               json.dumps({"resource_id": "search_501", "email": ALICE,
                                           "related_resource_id": "cache_502", "status": "PRESENT"}))
        self.data.add_activity("activity_link", "cache_502", "LINK_RESOURCE_IDENTITY",
                               "subject_reference=user_100 resource_id=cache_502")
        output, index = self.data.run(req)
        candidate_ids = {c["resource_id"] for c in index.diagnostics_by_case["synthetic_8"]["candidates"]}
        self.assertIn("search_501", candidate_ids)
        self.assertIn("cache_502", candidate_ids)
        cache_candidate = next(c for c in index.diagnostics_by_case["synthetic_8"]["candidates"]
                               if c["resource_id"] == "cache_502")
        self.assertIn("activity_link", {a["activity_id"] for a in cache_candidate["activities"]})
        output_steps = decode(output)
        finding_refs = {s["evidence_id"] for s in output_steps if s["phase"] == "FINDING"}
        self.assertTrue(finding_refs <= {"e_linked", "activity_link"})
        self.assertIn("e_linked", finding_refs)

    def test_tombstone_redacts_direct_identifiers_but_keeps_stable_user_reference(self) -> None:
        req = self.data.add_request("synthetic_9")
        self.data.add_evidence("e_tomb", "evidence/records/tomb.json",
                               json.dumps({"resource_id": "tombstone_601", "user_id": "user_100",
                                           "name": "Avery Example", "email": ALICE,
                                           "phone": "+1-555-0101", "email_hash": "a" * 64,
                                           "status": "PRESENT"}))
        output, _ = self.data.run(req)
        steps = decode(output)
        self.assertEqual(output["deletion_status"], "INCOMPLETE")
        self.assertEqual([(s["operation"], s["state"]) for s in steps if s["phase"] in {"FINDING", "REMEDIATION"}],
                         [("REPORT_EXPOSED_PII", "PRESENT"), ("REDACT_RECORD", "REDACTED")])
        self.assertEqual(steps[-1]["operation"], "VERIFY_RECORD_REDACTED")
        self.assertEqual(steps[0]["evidence_id"], "e_tomb")

    def test_retained_legal_record_is_verified_not_deleted(self) -> None:
        req = self.data.add_request("synthetic_10")
        self.data.add_evidence("e_hold", "evidence/records/hold.json",
                               json.dumps({"resource_id": "legal_701", "email": ALICE,
                                           "active": True, "status": "PRESENT"}))
        self.data.add_evidence("e_security", "evidence/records/security.json",
                               json.dumps({"resource_id": "audit_record_702", "email": ALICE,
                                           "retention_until": "2027-01-10T00:00:00Z", "status": "PRESENT"}))
        output, _ = self.data.run(req)
        steps = decode(output)
        self.assertEqual(output["deletion_status"], "COMPLETE")
        self.assertEqual([s["operation"] for s in steps], ["VERIFY_RECORD_PRESENT", "VERIFY_RECORD_PRESENT"])
        self.assertEqual({s["evidence_id"] for s in steps}, {"e_hold", "e_security"})

    def test_sync_and_restore_risks_have_findings_actions_and_verification(self) -> None:
        req = self.data.add_request("synthetic_11")
        self.data.add_evidence("e_flow", "evidence/records/flow.json",
                               json.dumps({"resource_id": "data_flow_801", "email": ALICE,
                                           "enabled": True, "status": "ACTIVE"}))
        self.data.add_evidence("e_import", "evidence/records/import.json",
                               json.dumps({"resource_id": "data_flow_803", "email": ALICE,
                                           "flow_type": "IMPORT", "enabled": True, "status": "ACTIVE"}))
        self.data.add_evidence("e_backup", "evidence/records/backup.json",
                               json.dumps({"resource_id": "backup_802", "email": ALICE,
                                           "restore_allowed": True, "status": "ACTIVE"}))
        output, _ = self.data.run(req)
        steps = decode(output)
        expected = {
            "data_flow_801": ("REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED"),
            "data_flow_803": ("REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED"),
            "backup_802": ("REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED"),
        }
        for rid, operations in expected.items():
            observed = tuple(s["operation"] for s in steps if s["resource_id"] == rid)
            self.assertEqual(observed, operations)
        self.assertEqual(output["deletion_status"], "INCOMPLETE")

    def test_duplicate_and_contradictory_rows_produce_one_remediation_per_resource(self) -> None:
        req = self.data.add_request("synthetic_12")
        payload = {"resource_id": "search_901", "email": ALICE, "status": "PRESENT"}
        self.data.add_evidence("e_dup1", "evidence/records/one.json", json.dumps(payload))
        self.data.add_evidence("e_dup2", "evidence/records/two.json", json.dumps(payload))
        self.data.add_evidence("e_absent", "evidence/records/three.json",
                               json.dumps({"resource_id": "search_901", "email": ALICE, "status": "ABSENT",
                                           "observed_at": "2026-01-10T11:30:00Z"}))
        output, _ = self.data.run(req)
        steps = decode(output)
        self.assertEqual(sum(s["phase"] == "REMEDIATION" and s["resource_id"] == "search_901" for s in steps), 1)
        self.assertEqual(sum(s["phase"] == "FINDING" and s["resource_id"] == "search_901" for s in steps), 1)

    def test_steps_use_allowed_pairs_and_are_sorted_and_deterministic(self) -> None:
        req = self.data.add_request("synthetic_13")
        self.data.add_evidence("e_search", "evidence/records/search.json",
                               json.dumps({"resource_id": "search_1001", "email": ALICE, "status": "PRESENT"}))
        self.data.add_evidence("e_cache", "evidence/records/cache.json",
                               json.dumps({"resource_id": "cache_1002", "email": ALICE, "status": "PRESENT"}))
        first, _ = self.data.run(req)
        second, _ = self.data.run(req)
        self.assertEqual(first, second)
        allowed = {
            "FINDING": {"REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT",
                        "REPORT_ACTIVE_DATA_FLOW": "ACTIVE", "REPORT_RESTORE_RISK": "ACTIVE"},
            "REMEDIATION": {"DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED",
                            "DELETE_RECORD": "ABSENT", "REDACT_RECORD": "REDACTED",
                            "ANONYMIZE_RECORD": "ANONYMIZED"},
            "VERIFICATION": {"VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT",
                              "VERIFY_RECORD_REDACTED": "REDACTED", "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
                              "VERIFY_DATA_FLOW_DISABLED": "DISABLED", "VERIFY_RESTORE_BLOCKED": "BLOCKED"},
        }
        steps = decode(first)
        for number, step in enumerate(steps, 1):
            self.assertEqual(step["step_no"], number)
            self.assertEqual(step["state"], allowed[step["phase"]][step["operation"]])
            if step["phase"] == "FINDING":
                self.assertIn(step["evidence_id"], {"e_search", "e_cache"})
            else:
                self.assertEqual(step["evidence_id"], "")
        self.assertEqual([agent.PHASE_RANK[s["phase"]] for s in steps],
                         sorted(agent.PHASE_RANK[s["phase"]] for s in steps))
        sort_key = lambda s: (agent.PHASE_RANK[s["phase"]],
                              agent.OPERATION_RANK[s["phase"]][s["operation"]],
                              s["system_id"], s["resource_id"])
        self.assertEqual([sort_key(s) for s in steps], sorted(sort_key(s) for s in steps))

    def test_shared_resource_with_conflicting_identity_isolated_between_users(self) -> None:
        alice_req = self.data.add_request("synthetic_14", email=ALICE)
        bob_req = self.data.add_request("synthetic_15", email=BOB)
        self.data.add_evidence("e_alice", "evidence/records/alice.json",
                               json.dumps({"resource_id": "search_shared901", "email": ALICE,
                                           "status": "PRESENT", "observed_at": "2026-01-10T10:30:00Z"}))
        self.data.add_evidence("e_bob", "evidence/records/bob.json",
                               json.dumps({"resource_id": "search_shared901", "email": BOB,
                                           "status_code": 404, "observed_at": "2026-01-10T11:30:00Z"}))
        self.data.finalize()
        maps = agent.build_identity_maps(self.data.root)
        activities = agent.load_activity(self.data.root)
        index = agent.EvidenceIndex(self.data.root)
        nearest = agent.assign_activity_nearest_case([alice_req, bob_req], activities)
        alice = agent.build_case_output(alice_req, [alice_req, bob_req], index, activities, maps, nearest)
        bob = agent.build_case_output(bob_req, [alice_req, bob_req], index, activities, maps, nearest)
        self.assertEqual(alice["deletion_status"], "INCOMPLETE")
        self.assertEqual(bob["deletion_status"], "COMPLETE")
        alice_steps = decode(alice)
        self.assertEqual(alice_steps[0]["evidence_id"], "e_alice")


if __name__ == "__main__":
    unittest.main(verbosity=2)
