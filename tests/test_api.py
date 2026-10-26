from __future__ import annotations

import csv
import logging
import os
import sys
import time
import io
import json
import shutil
import subprocess
import stat
import tempfile
import threading
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from fastapi.testclient import TestClient

from ghost_audit.api import create_app
from ghost_audit.service import AppSettings, AuditService
from ghost_audit.engine import run_audit
from ghost_audit.models import AuditConfig

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "synthetic" / "bundle"
REQUESTS = DEMO / "requests.csv"


def zip_bundle(*, manifest_override: str | None = None, extra: dict[str, bytes] | None = None,
               include: set[str] | None = None) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(DEMO.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(DEMO).as_posix()
            if include is not None and rel not in include:
                continue
            data = path.read_bytes()
            if rel == "evidence_files.csv" and manifest_override is not None:
                data = manifest_override.encode()
            archive.writestr(rel, data)
        for name, content in (extra or {}).items():
            archive.writestr(name, content)
    return out.getvalue()


def multipart(request_bytes: bytes | None = None, bundle: bytes | None = None):
    return {
        "request_csv": ("requests.csv", request_bytes if request_bytes is not None else REQUESTS.read_bytes(), "text/csv"),
        "evidence_bundle": ("bundle.zip", bundle if bundle is not None else zip_bundle(), "application/zip"),
    }


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="ghost-api-test-", dir=ROOT)
        self.root = Path(self.temp.name)
        self.settings = AppSettings(self.root / "data", max_upload_bytes=4 * 1024 * 1024,
                                    max_zip_entries=200, max_uncompressed_bytes=4 * 1024 * 1024,
                                    execution_timeout_seconds=30, retention_hours=24)
        self.service = AuditService(self.settings)
        self.client = TestClient(create_app(self.settings, self.service))

    def tearDown(self) -> None:
        self.client.close()
        self.temp.cleanup()

    def submit(self, request_bytes: bytes | None = None, bundle: bytes | None = None) -> dict:
        response = self.client.post("/api/audits", files=multipart(request_bytes, bundle))
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def test_health_and_version(self) -> None:
        health = self.client.get("/api/health")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json(), {"status": "ok", "engine_available": True,
                                         "implementation_mode": "deterministic_local"})
        version = self.client.get("/api/version").json()
        self.assertEqual(version["implementation_mode"], "deterministic_local")
        self.assertFalse(version["hosted_model_calls"])
        self.assertEqual(version["retention_hours"], 24)

    def test_validate_and_submit_synthetic_bundle_and_retrieve_case(self) -> None:
        validation = self.client.post("/api/validate", files=multipart())
        self.assertEqual(validation.status_code, 200, validation.text)
        self.assertTrue(validation.json()["valid"])
        self.assertEqual(validation.json()["request_count"], 2)
        accepted = self.submit()
        self.assertEqual(accepted["summary"]["validation_status"], "PASSED")
        self.assertEqual(accepted["summary"]["request_count"], 2)
        detail = self.client.get(f"/api/audits/{accepted['audit_id']}/cases/demo_case_001")
        self.assertEqual(detail.status_code, 200)
        case = detail.json()
        self.assertEqual(case["deletion_status"], "INCOMPLETE")
        self.assertEqual(case["evidence_references"], sorted(set(case["evidence_references"])))

    def test_status_filters_pagination_and_sorting(self) -> None:
        audit = self.submit()["audit_id"]
        page = self.client.get(f"/api/audits/{audit}/cases?offset=0&limit=1")
        self.assertEqual(page.status_code, 200)
        self.assertEqual(page.json()["total"], 2)
        self.assertEqual(page.json()["limit"], 1)
        self.assertEqual(len(page.json()["items"]), 1)
        filtered = self.client.get(f"/api/audits/{audit}/cases?status=NOT_APPLICABLE")
        self.assertEqual(filtered.json()["total"], 1)
        self.assertEqual(filtered.json()["items"][0]["case_id"], "demo_case_002")
        descending = self.client.get(f"/api/audits/{audit}/cases?sort_by=deletion_status&order=desc")
        self.assertEqual(descending.json()["items"][0]["deletion_status"], "NOT_APPLICABLE")

    def test_invalid_csv_has_stable_error_and_does_not_leak_content(self) -> None:
        response = self.client.post("/api/validate", files=multipart(b"email\nsecret@example.invalid\n"))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "INVALID_INPUT")
        self.assertNotIn("secret@example.invalid", response.text)

    def test_missing_required_bundle_file_is_rejected(self) -> None:
        names = {p.relative_to(DEMO).as_posix() for p in DEMO.rglob("*") if p.is_file()}
        names.remove("deletion_rules.csv")
        response = self.client.post("/api/validate", files=multipart(bundle=zip_bundle(include=names)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "INVALID_EVIDENCE_BUNDLE")

    def test_zip_path_traversal_is_rejected(self) -> None:
        response = self.client.post("/api/validate", files=multipart(bundle=zip_bundle(extra={"../escape.txt": b"x"})))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "INVALID_EVIDENCE_BUNDLE")

    def test_oversized_uncompressed_archive_is_rejected(self) -> None:
        settings = AppSettings(self.root / "small-data", max_upload_bytes=100000,
                               max_zip_entries=200, max_uncompressed_bytes=200,
                               execution_timeout_seconds=30, retention_hours=24)
        client = TestClient(create_app(settings))
        try:
            response = client.post("/api/validate", files=multipart(bundle=zip_bundle()))
            self.assertEqual(response.status_code, 413)
        finally:
            client.close()

    def test_manifest_traversal_is_rejected(self) -> None:
        malicious = "file_id,file_path,origin,captured_at\ndemo_x,../../escape.json,synthetic,2026-10-10T00:00:00Z\n"
        response = self.client.post("/api/validate", files=multipart(bundle=zip_bundle(manifest_override=malicious)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "INVALID_EVIDENCE_BUNDLE")

    def test_unsupported_file_type_is_rejected(self) -> None:
        response = self.client.post("/api/validate", files=multipart(bundle=zip_bundle(extra={"evidence/payload.exe": b"x"})))
        self.assertEqual(response.status_code, 415)
        self.assertEqual(response.json()["error"]["code"], "UNSUPPORTED_FILE")

    def test_oversized_upload_is_rejected(self) -> None:
        settings = AppSettings(self.root / "upload-limit-data", max_upload_bytes=16,
                               max_zip_entries=200, max_uncompressed_bytes=4 * 1024 * 1024,
                               execution_timeout_seconds=30, retention_hours=24)
        client = TestClient(create_app(settings))
        try:
            response = client.post("/api/validate", files=multipart())
            self.assertEqual(response.status_code, 413)
            self.assertEqual(response.json()["error"]["code"], "INVALID_INPUT")
        finally:
            client.close()

    def test_zip_symlink_entry_is_rejected(self) -> None:
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(DEMO.rglob("*")):
                if path.is_file(): archive.write(path, path.relative_to(DEMO).as_posix())
            link = zipfile.ZipInfo("evidence/records/link.txt")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(link, "target.txt")
        response = self.client.post("/api/validate", files=multipart(bundle=out.getvalue()))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "INVALID_EVIDENCE_BUNDLE")

    def test_excessive_zip_entry_count_is_rejected(self) -> None:
        settings = AppSettings(self.root / "entry-limit-data", max_upload_bytes=4 * 1024 * 1024,
                               max_zip_entries=2, max_uncompressed_bytes=4 * 1024 * 1024,
                               execution_timeout_seconds=30, retention_hours=24)
        client = TestClient(create_app(settings))
        try:
            response = client.post("/api/validate", files=multipart())
            self.assertEqual(response.status_code, 413)
        finally:
            client.close()

    def test_output_validation_failure_is_not_published_as_success(self) -> None:
        def bad_output(command, **kwargs):
            target = Path(command[command.index("--output") + 1])
            target.write_text("wrong,header\na,b\n", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "", "")
        settings = AppSettings(self.root / "validation-fail-data", max_upload_bytes=4 * 1024 * 1024,
                               max_zip_entries=200, max_uncompressed_bytes=4 * 1024 * 1024,
                               execution_timeout_seconds=30, retention_hours=24)
        client = TestClient(create_app(settings, AuditService(settings, runner=bad_output)))
        try:
            response = client.post("/api/audits", files=multipart())
            self.assertEqual(response.status_code, 500)
            self.assertEqual(response.json()["error"]["code"], "VALIDATION_FAILED")
            audit_id = next(settings.data_dir.iterdir()).name
            self.assertEqual(json.loads((settings.data_dir / audit_id / "metadata.json").read_text())["status"], "FAILED")
            self.assertFalse((settings.data_dir / audit_id / "output.csv").exists())
        finally:
            client.close()

    def test_timeout_is_bounded_persisted_and_cleans_inputs(self) -> None:
        def timeout(*_args, **kwargs):
            raise subprocess.TimeoutExpired(kwargs.get("args", "ghost-audit"), 1)
        settings = AppSettings(self.root / "timeout-data", max_upload_bytes=4 * 1024 * 1024,
                               max_zip_entries=200, max_uncompressed_bytes=4 * 1024 * 1024,
                               execution_timeout_seconds=1, retention_hours=24)
        service = AuditService(settings, runner=timeout)
        client = TestClient(create_app(settings, service))
        try:
            response = client.post("/api/audits", files=multipart())
            self.assertEqual(response.status_code, 504)
            self.assertEqual(response.json()["error"]["code"], "AUDIT_TIMEOUT")
            audit_id = next(settings.data_dir.iterdir()).name
            record = client.get(f"/api/audits/{audit_id}").json()
            self.assertEqual(record["status"], "FAILED")
            self.assertFalse((settings.data_dir / audit_id / "bundle").exists())
        finally:
            client.close()

    def test_subprocess_failure_is_structured_and_cleans_inputs(self) -> None:
        class Failed:
            returncode = 7
        settings = AppSettings(self.root / "fail-data", max_upload_bytes=4 * 1024 * 1024,
                               max_zip_entries=200, max_uncompressed_bytes=4 * 1024 * 1024,
                               execution_timeout_seconds=30, retention_hours=24)
        client = TestClient(create_app(settings, AuditService(settings, runner=lambda *a, **k: Failed())))
        try:
            response = client.post("/api/audits", files=multipart())
            self.assertEqual(response.status_code, 500)
            self.assertEqual(response.json()["error"]["code"], "AUDIT_EXECUTION_FAILED")
            audit_id = next(settings.data_dir.iterdir()).name
            self.assertFalse((settings.data_dir / audit_id / "requests.csv").exists())
        finally:
            client.close()

    def test_audit_deletion_removes_inputs_results_and_previews(self) -> None:
        audit_id = self.submit()["audit_id"]
        audit_dir = self.settings.data_dir / audit_id
        self.assertTrue((audit_dir / "bundle").is_dir())
        response = self.client.delete(f"/api/audits/{audit_id}")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["deleted"])
        self.assertFalse(audit_dir.exists())
        self.assertEqual(self.client.get(f"/api/audits/{audit_id}").status_code, 404)

    def test_expired_audits_are_cleaned(self) -> None:
        audit_id = self.submit()["audit_id"]
        metadata_path = self.settings.data_dir / audit_id / "metadata.json"
        metadata = json.loads(metadata_path.read_text())
        metadata["created_at"] = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
        metadata_path.write_text(json.dumps(metadata))
        self.assertEqual(self.service.cleanup_expired(), 1)
        self.assertFalse((self.settings.data_dir / audit_id).exists())

    def test_evidence_preview_is_manifest_linked_and_bounded(self) -> None:
        audit_id = self.submit()["audit_id"]
        preview = self.client.get(f"/api/audits/{audit_id}/evidence/demo_evidence_account/preview")
        self.assertEqual(preview.status_code, 200)
        self.assertTrue(preview.json()["available"])
        self.assertEqual(preview.json()["source_file"], "evidence/records/account.json")
        self.assertIn("account_101", preview.json()["excerpt"])
        missing = self.client.get(f"/api/audits/{audit_id}/evidence/activity_fake/preview")
        self.assertFalse(missing.json()["available"])
        self.assertIn("not a uniquely mapped", missing.json()["message"])

    def test_empty_incomplete_plan_is_marked_needs_review(self) -> None:
        files = {
            "requests.csv": ("requests.csv", b"case_id,email,requested_at,reported_status,reported_at,audit_at,request_text\nempty_case,unknown@example.invalid,2026-10-10T00:00:00Z,NOT_STARTED,2026-10-10T00:00:00Z,2026-10-10T12:00:00Z,Please delete my account\n"),
            "evidence_files.csv": ("evidence_files.csv", b"file_id,file_path,origin,captured_at\n"),
            "user_identities.csv": ("user_identities.csv", b"user_id,name,email,phone,email_hash,updated_at\n"),
            "user_audit_log.csv": ("user_audit_log.csv", b"audit_id,user_id,event_time,field_name,old_value,new_value\n"),
            "system_activity.csv": ("system_activity.csv", b"activity_id,event_time,event_type,source_system,target_system,resource_id,reported_result,details\n"),
            "deletion_rules.csv": ("deletion_rules.csv", b"rule_id,data_category,condition,required_treatment\n"),
        }
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as archive:
            for name, (_fn, data) in files.items(): archive.writestr(name, data)
        accepted = self.submit(files["requests.csv"][1], out.getvalue())
        self.assertEqual(accepted["summary"]["needs_review_count"], 1)
        self.assertEqual(accepted["summary"]["needs_review_percent_of_incomplete"], 100.0)
        page = self.client.get(f"/api/audits/{accepted['audit_id']}/cases?status=INCOMPLETE").json()
        self.assertEqual(page["items"][0]["review_label"], "NEEDS_REVIEW")
        detail = self.client.get(f"/api/audits/{accepted['audit_id']}/cases/empty_case").json()
        self.assertEqual(detail["steps"], [])

    def test_pii_free_default_logs(self) -> None:
        captured: list[str] = []
        class Capture(logging.Handler):
            def emit(self, record):
                captured.append(self.format(record))
        logger = logging.getLogger("ghost_audit")
        handler = Capture()
        logger.addHandler(handler)
        try:
            response = self.client.post("/api/validate", files=multipart(b"email\nprivate@example.invalid\n"))
        finally:
            logger.removeHandler(handler)
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("private@example.invalid", "\n".join(captured))

    def test_concurrent_audit_limit_is_enforced(self) -> None:
        started, release = threading.Event(), threading.Event()
        real_run = subprocess.run
        def slow_runner(*args, **kwargs):
            started.set()
            if not release.wait(10):
                raise TimeoutError("test did not release runner")
            return real_run(*args, **kwargs)
        settings = AppSettings(self.root / "concurrency-data", max_upload_bytes=4 * 1024 * 1024,
                               max_zip_entries=200, max_uncompressed_bytes=4 * 1024 * 1024,
                               execution_timeout_seconds=30, max_concurrent_audits=1, retention_hours=24)
        service = AuditService(settings, runner=slow_runner)
        app = create_app(settings, service)
        first_client, second_client = TestClient(app), TestClient(app)
        result: list[object] = []
        thread = threading.Thread(target=lambda: result.append(first_client.post("/api/audits", files=multipart())))
        try:
            thread.start()
            self.assertTrue(started.wait(10))
            response = second_client.post("/api/audits", files=multipart())
            self.assertEqual(response.status_code, 429)
            self.assertEqual(response.json()["error"]["code"], "CONCURRENCY_LIMIT")
        finally:
            release.set()
            thread.join(15)
            first_client.close()
            second_client.close()
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].status_code, 201)

    def test_api_output_matches_original_engine_csv(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.root) as tmp:
            reference = Path(tmp) / "reference.csv"
            run_audit(AuditConfig(REQUESTS, DEMO, reference))
            audit_id = self.submit()["audit_id"]
            response = self.client.get(f"/api/audits/{audit_id}/download")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, reference.read_bytes())

    def test_download_and_detail_endpoints(self) -> None:
        audit_id = self.submit()["audit_id"]
        csv_response = self.client.get(f"/api/audits/{audit_id}/download")
        self.assertEqual(csv_response.status_code, 200)
        self.assertEqual(csv_response.headers["content-type"].split(";")[0], "text/csv")
        detail = self.client.get(f"/api/audits/{audit_id}/detail.json")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(len(detail.json()["cases"]), 2)

    def test_missing_audit_and_case_have_stable_errors(self) -> None:
        missing = self.client.get("/api/audits/00000000000000000000000000000000")
        self.assertEqual(missing.status_code, 404)
        case = self.submit()["audit_id"]
        missing_case = self.client.get(f"/api/audits/{case}/cases/not_a_case")
        self.assertEqual(missing_case.status_code, 404)
        self.assertEqual(missing_case.json()["error"]["code"], "CASE_NOT_FOUND")


    def test_production_auth_fails_closed_and_protects_every_sensitive_endpoint(self) -> None:
        audit_id = self.submit()["audit_id"]
        token = "phase12-test-token-" + ("x" * 40)
        production = AppSettings(self.settings.data_dir, mode="production", bearer_token=token)
        secure = TestClient(create_app(production, self.service))
        self.assertNotIn(token, repr(production))
        protected = [
            ("POST", "/api/validate"),
            ("POST", "/api/audits"),
            ("GET", f"/api/audits/{audit_id}"),
            ("GET", f"/api/audits/{audit_id}/cases"),
            ("GET", f"/api/audits/{audit_id}/cases/demo_case_001"),
            ("GET", f"/api/audits/{audit_id}/evidence/demo_evidence_account/preview"),
            ("GET", f"/api/audits/{audit_id}/download"),
            ("GET", f"/api/audits/{audit_id}/detail.json"),
            ("DELETE", f"/api/audits/{audit_id}"),
        ]
        try:
            for method, path in protected:
                files = multipart() if method == "POST" else None
                for headers in ({}, {"Authorization": "Bearer incorrect-token"}):
                    response = secure.request(method, path, headers=headers, files=files)
                    self.assertEqual(response.status_code, 401, (method, path, response.text))
                    self.assertEqual(response.json()["error"]["code"], "AUTHENTICATION_REQUIRED")
                    self.assertNotIn(token, response.text)
            health = secure.get("/api/health")
            self.assertEqual(health.status_code, 200)
            self.assertNotIn(token, health.text)
            self.assertEqual(secure.get("/api/openapi.json").status_code, 404)
            valid = {"Authorization": f"Bearer {token}"}
            self.assertEqual(secure.get(f"/api/audits/{audit_id}/cases/demo_case_001",
                                         headers=valid).status_code, 200)
            self.assertEqual(secure.post("/api/validate", files=multipart(), headers=valid).status_code, 200)
            created = secure.post("/api/audits", files=multipart(), headers=valid)
            self.assertEqual(created.status_code, 201, created.text)
            self.assertEqual(secure.delete(f"/api/audits/{created.json()['audit_id']}",
                                           headers=valid).status_code, 200)
        finally:
            secure.close()

    def test_production_auth_configuration_rejects_missing_or_weak_secret(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing"):
            create_app(AppSettings(self.root / "missing-secret", mode="production"))
        with self.assertRaisesRegex(ValueError, "at least 32"):
            create_app(AppSettings(self.root / "weak-secret", mode="production",
                                   bearer_token="short"))
        with self.assertRaisesRegex(ValueError, "development or production"):
            create_app(AppSettings(self.root / "invalid-mode", mode="staging",
                                   bearer_token="x" * 40))

    def test_health_and_version_never_disclose_secret(self) -> None:
        token = "health-check-secret-" + ("z" * 40)
        settings = AppSettings(self.root / "health-secret", mode="production", bearer_token=token)
        client = TestClient(create_app(settings))
        try:
            for path in ("/api/health", "/api/version"):
                response = client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertNotIn(token, response.text)
                self.assertNotIn("bearer_token", response.text)
        finally:
            client.close()

    def test_cors_is_explicit_and_disallowed_origin_gets_no_allow_header(self) -> None:
        settings = AppSettings(self.root / "cors-data", cors_origins=("https://trusted.example",))
        client = TestClient(create_app(settings))
        try:
            disallowed = client.options("/api/health", headers={
                "Origin": "https://attacker.example",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "authorization",
            })
            self.assertNotIn("access-control-allow-origin", disallowed.headers)
            allowed = client.options("/api/health", headers={
                "Origin": "https://trusted.example",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "authorization",
            })
            self.assertEqual(allowed.headers.get("access-control-allow-origin"), "https://trusted.example")
        finally:
            client.close()
        with self.assertRaisesRegex(ValueError, "explicit"):
            create_app(AppSettings(self.root / "wildcard-cors", cors_origins=("*",)))

    def test_audits_are_isolated_from_other_audit_ids_and_deletion(self) -> None:
        def request_for(case_id: str) -> bytes:
            with REQUESTS.open(encoding="utf-8", newline="") as handle:
                row = next(csv.DictReader(handle))
            row["case_id"] = case_id
            out = io.StringIO(newline="")
            writer = csv.DictWriter(out, fieldnames=row.keys(), lineterminator="\n")
            writer.writeheader()
            writer.writerow(row)
            return out.getvalue().encode()
        first = self.submit(request_for("isolated_a"))["audit_id"]
        second = self.submit(request_for("isolated_b"))["audit_id"]
        self.assertEqual(self.client.get(f"/api/audits/{first}/cases/isolated_a").status_code, 200)
        self.assertEqual(self.client.get(f"/api/audits/{first}/cases/isolated_b").status_code, 404)
        first_bundle = self.settings.data_dir / first / "bundle"
        second_bundle = self.settings.data_dir / second / "bundle"
        self.assertNotEqual(first_bundle.resolve(), second_bundle.resolve())
        self.assertEqual(self.client.delete(f"/api/audits/{first}").status_code, 200)
        self.assertTrue(second_bundle.is_dir())
        self.assertEqual(self.client.get(f"/api/audits/{second}/cases/isolated_b").status_code, 200)

    def test_corrupt_json_evidence_fails_safely_without_publishing_partial_output(self) -> None:
        old = (DEMO / "evidence_files.csv").read_text(encoding="utf-8")
        manifest = old + "bad_json,evidence/records/corrupt.json,synthetic,2026-10-10T11:00:00Z\n"
        accepted = self.submit(bundle=zip_bundle(manifest_override=manifest,
                                                 extra={"evidence/records/corrupt.json": b"{not valid json"}))
        self.assertEqual(accepted["summary"]["validation_status"], "PASSED")
        rows = self.client.get(f"/api/audits/{accepted['audit_id']}/cases?limit=10")
        self.assertEqual(rows.status_code, 200)

    def test_untrusted_preview_is_returned_as_plain_text_not_markup(self) -> None:
        from ghost_audit.dashboard import _display_safe_excerpt
        marker = "<script>window.localStorage.clear()</script>"
        old = (DEMO / "evidence_files.csv").read_text(encoding="utf-8")
        manifest = old + "unsafe_text,evidence/records/unsafe.txt,synthetic,2026-10-10T11:00:00Z\n"
        accepted = self.submit(bundle=zip_bundle(manifest_override=manifest,
                                                 extra={"evidence/records/unsafe.txt": marker.encode()}))
        aid = accepted["audit_id"]
        response = self.client.get(f"/api/audits/{aid}/evidence/unsafe_text/preview")
        self.assertTrue(response.json()["available"])
        self.assertEqual(response.json()["excerpt"], marker)
        with patch("ghost_audit.dashboard.st.text") as render_text:
            _display_safe_excerpt(marker)
        render_text.assert_called_once_with(marker)
        self.assertFalse(response.json()["truncated"])

    def test_dashboard_sanitizes_unauthorized_and_unavailable_api_errors(self) -> None:
        from ghost_audit.dashboard import _api_call
        token = "dashboard-secret-" + ("q" * 40)
        def unauthorized(request, **_kwargs):
            self.assertEqual(request.get_header("Authorization"), f"Bearer {token}")
            content = json.dumps({"error": {"code": "AUTHENTICATION_REQUIRED",
                                            "message": token}}).encode()
            raise HTTPError(request.full_url, 401, "Unauthorized", {}, io.BytesIO(content))
        with patch("urllib.request.urlopen", side_effect=unauthorized):
            with self.assertRaisesRegex(RuntimeError, "Authentication failed") as caught:
                _api_call("http://127.0.0.1:8000", "/api/health", token=token)
        self.assertNotIn(token, str(caught.exception))
        with patch("urllib.request.urlopen", side_effect=URLError(token)):
            with self.assertRaisesRegex(RuntimeError, "Cannot reach") as caught:
                _api_call("http://127.0.0.1:8000", "/api/health", token=token)
        self.assertNotIn(token, str(caught.exception))

    @unittest.skipIf(os.name == "nt", "POSIX process groups are verified in Linux CI; Windows taskkill path is platform-specific")
    def test_timeout_terminates_engine_descendants(self) -> None:
        settings = AppSettings(self.root / "tree-kill-data", execution_timeout_seconds=1)
        service = AuditService(settings)
        pid_file = self.root / "descendant.pid"
        child_code = "import time; time.sleep(60)"
        parent_code = ("import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c',sys.argv[2]]); "
                       "open(sys.argv[1],'w').write(str(p.pid)); time.sleep(60)")
        command = [sys.executable, "-c", parent_code, str(pid_file), child_code]
        with self.assertRaises(subprocess.TimeoutExpired):
            service._run_engine(command, ROOT)
        self.assertTrue(pid_file.exists())
        child_pid = int(pid_file.read_text())
        deadline = time.time() + 5
        alive = True
        while time.time() < deadline:
            try:
                os.kill(child_pid, 0)
                proc_stat = Path(f"/proc/{child_pid}/stat")
                if proc_stat.exists() and proc_stat.read_text().split()[2] == "Z":
                    alive = False
                    break
            except ProcessLookupError:
                alive = False
                break
            time.sleep(0.05)
        self.assertFalse(alive, f"descendant PID {child_pid} survived process-group termination")

    def test_auth_token_is_sent_in_header_and_never_in_dashboard_url(self) -> None:
        from ghost_audit.dashboard import _api_call
        token = "header-only-secret-" + ("m" * 40)
        seen = []
        def fail(request, **_kwargs):
            seen.append(request)
            raise URLError("offline")
        with patch("urllib.request.urlopen", side_effect=fail):
            with self.assertRaises(RuntimeError):
                _api_call("http://127.0.0.1:8000", "/api/audits/test", token=token)
        self.assertEqual(seen[0].get_header("Authorization"), f"Bearer {token}")
        self.assertNotIn(token, seen[0].full_url)
        with self.assertRaisesRegex(RuntimeError, "credentials"):
            _api_call("http://user:pass@127.0.0.1:8000", "/api/health")


if __name__ == "__main__":
    unittest.main()
