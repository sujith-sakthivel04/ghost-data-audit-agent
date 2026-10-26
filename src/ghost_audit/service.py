"""Local audit orchestration, upload validation, persistence, and privacy controls."""
from __future__ import annotations

import csv
import io
import json
import os
import signal
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable
from urllib.parse import urlsplit

from . import __version__
from .config import ConfigurationError, validate_manifest_paths, validate_request_path
from .engine import validate_output_file
from . import _challenge_engine as core

REQUEST_FIELDS = {"case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"}
REQUIRED_BUNDLE = {"evidence_files.csv", "user_identities.csv", "user_audit_log.csv", "system_activity.csv", "deletion_rules.csv"}
ALLOWED_EXTENSIONS = {".csv", ".json", ".txt", ".log", ".sql", ".pdf", ".png", ".jpg", ".jpeg", ".webp"}
AUDIT_ID_RE = re.compile(r"^[a-f0-9]{32}$")
CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


@dataclass(frozen=True)
class AppSettings:
    data_dir: Path
    max_upload_bytes: int = 50 * 1024 * 1024
    max_zip_entries: int = 5000
    max_uncompressed_bytes: int = 250 * 1024 * 1024
    execution_timeout_seconds: int = 300
    max_concurrent_audits: int = 1
    retention_hours: int = 24
    mode: str = "development"
    bearer_token: str | None = field(default=None, repr=False)
    auth_required: bool | None = None
    cors_origins: tuple[str, ...] = ()

    @property
    def authentication_enabled(self) -> bool:
        return self.mode == "production" or self.auth_required is True or bool(self.bearer_token)

    def validate_security(self) -> None:
        if self.mode not in {"development", "production"}:
            raise ValueError("GHOST_AUDIT_MODE must be development or production")
        token = self.bearer_token
        if token and (len(token) < 32 or token.strip() != token or any(ch.isspace() for ch in token)):
            raise ValueError("Bearer token must be at least 32 non-whitespace characters")
        if self.authentication_enabled and not token:
            raise ValueError("Authentication is enabled but GHOST_AUDIT_BEARER_TOKEN is missing")
        for origin in self.cors_origins:
            parsed = urlsplit(origin)
            if (origin == "*" or not origin or parsed.scheme not in {"http", "https"} or
                    not parsed.netloc or parsed.username or parsed.password or parsed.path not in {"", "/"} or
                    parsed.query or parsed.fragment or origin != origin.strip()):
                raise ValueError("CORS origins must be explicit HTTP(S) origins without paths or credentials")

    @classmethod
    def from_env(cls) -> "AppSettings":
        default_root = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "GhostDataAudit" / "audits"
        return cls(
            data_dir=Path(os.environ.get("GHOST_AUDIT_DATA_DIR", default_root)).expanduser(),
            max_upload_bytes=_env_int("GHOST_AUDIT_MAX_UPLOAD_BYTES", 50 * 1024 * 1024, 1),
            max_zip_entries=_env_int("GHOST_AUDIT_MAX_ZIP_ENTRIES", 5000, 1),
            max_uncompressed_bytes=_env_int("GHOST_AUDIT_MAX_UNCOMPRESSED_BYTES", 250 * 1024 * 1024, 1),
            execution_timeout_seconds=_env_int("GHOST_AUDIT_TIMEOUT_SECONDS", 300, 1),
            max_concurrent_audits=_env_int("GHOST_AUDIT_MAX_CONCURRENT", 1, 1),
            retention_hours=_env_int("GHOST_AUDIT_RETENTION_HOURS", 24, 1),
            mode=os.environ.get("GHOST_AUDIT_MODE", "development").strip().casefold(),
            bearer_token=os.environ.get("GHOST_AUDIT_BEARER_TOKEN") or None,
            auth_required=_env_bool_or_none("GHOST_AUDIT_AUTH_REQUIRED"),
            cors_origins=tuple(origin.strip() for origin in os.environ.get("GHOST_AUDIT_CORS_ORIGINS", "").split(",") if origin.strip()),
        )


def _env_bool_or_none(name: str) -> bool | None:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return None
    return value.strip().casefold() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int) -> int:
    try:
        return max(minimum, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


class AuditServiceError(Exception):
    def __init__(self, code: str, message: str, status_code: int):
        super().__init__(message)
        self.code, self.message, self.status_code = code, message, status_code


class AuditService:
    def __init__(self, settings: AppSettings, runner: Callable[..., Any] | None = None):
        self.settings = settings
        self.runner = runner
        self._slots = threading.BoundedSemaphore(settings.max_concurrent_audits)
        self._preview_cache: dict[tuple[str, str, int, int], str] = {}
        self.root = settings.data_dir.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            try:
                self.root.chmod(0o700)
            except OSError:
                pass

    def _audit_dir(self, audit_id: str) -> Path:
        if not AUDIT_ID_RE.fullmatch(audit_id):
            raise AuditServiceError("AUDIT_NOT_FOUND", "Audit was not found.", 404)
        directory = (self.root / audit_id).resolve()
        if not directory.is_relative_to(self.root):
            raise AuditServiceError("AUDIT_NOT_FOUND", "Audit was not found.", 404)
        return directory

    @staticmethod
    def validate_requests(data: bytes) -> list[dict[str, str]]:
        try:
            text = data.decode("utf-8-sig")
            reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
            fieldnames = reader.fieldnames or []
            header = set(fieldnames)
            missing = REQUEST_FIELDS - header
            if missing or len(header) != len(fieldnames) or any(not name.strip() for name in fieldnames):
                raise AuditServiceError("INVALID_INPUT", "Request CSV is missing required or has duplicate columns.", 400)
            rows = list(reader)
        except (UnicodeDecodeError, csv.Error):
            raise AuditServiceError("INVALID_INPUT", "Request CSV must be valid UTF-8 CSV.", 400) from None
        if not rows:
            raise AuditServiceError("INVALID_INPUT", "Request CSV contains no data rows.", 400)
        ids = [str(row.get("case_id", "")).strip() for row in rows]
        if (any(not CASE_ID_RE.fullmatch(cid) for cid in ids) or
                any(str(row.get("case_id", "")) != cid for row, cid in zip(rows, ids)) or
                len(set(ids)) != len(ids)):
            raise AuditServiceError("INVALID_INPUT", "Request case_id values must be trimmed, safe, non-empty, and unique.", 400)
        if any(any(value is None for value in row.values()) for row in rows):
            raise AuditServiceError("INVALID_INPUT", "Request CSV contains a malformed row.", 400)
        return rows

    def _zip_members(self, archive: bytes) -> list[tuple[str, zipfile.ZipInfo]]:
        try:
            zf = zipfile.ZipFile(io.BytesIO(archive))
        except (zipfile.BadZipFile, OSError):
            raise AuditServiceError("INVALID_EVIDENCE_BUNDLE", "Evidence bundle must be a valid ZIP archive.", 400) from None
        with zf:
            infos = zf.infolist()
            if len(infos) > self.settings.max_zip_entries:
                raise AuditServiceError("INVALID_EVIDENCE_BUNDLE", "Evidence bundle has too many archive entries.", 413)
            total = 0
            names: set[str] = set()
            validated: list[tuple[str, zipfile.ZipInfo]] = []
            for info in infos:
                raw = info.filename
                if not raw or "\x00" in raw or raw.startswith(("/", "\\")):
                    raise AuditServiceError("INVALID_EVIDENCE_BUNDLE", "Evidence bundle contains an unsafe path.", 400)
                normalized = raw.replace("\\", "/")
                posix, windows = PurePosixPath(normalized), PureWindowsPath(raw)
                raw_parts = normalized.split("/")
                if info.is_dir() and raw_parts and raw_parts[-1] == "":
                    raw_parts = raw_parts[:-1]
                if windows.is_absolute() or windows.drive or any(part in {".", "..", ""} for part in raw_parts):
                    raise AuditServiceError("INVALID_EVIDENCE_BUNDLE", "Evidence bundle contains an unsafe path.", 400)
                if any(part in {".", ".."} for part in posix.parts):
                    raise AuditServiceError("INVALID_EVIDENCE_BUNDLE", "Evidence bundle contains an unsafe path.", 400)
                name = posix.as_posix().rstrip("/")
                if not name:
                    continue
                key = name.casefold()
                if key in names:
                    raise AuditServiceError("INVALID_EVIDENCE_BUNDLE", "Evidence bundle contains duplicate paths.", 400)
                names.add(key)
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    raise AuditServiceError("INVALID_EVIDENCE_BUNDLE", "Evidence bundle may not contain symbolic links.", 400)
                if info.flag_bits & 0x1:
                    raise AuditServiceError("INVALID_EVIDENCE_BUNDLE", "Encrypted ZIP entries are not supported.", 400)
                if not info.is_dir():
                    if Path(name).suffix.casefold() not in ALLOWED_EXTENSIONS:
                        raise AuditServiceError("UNSUPPORTED_FILE", "Evidence bundle contains an unsupported file type.", 415)
                    total += info.file_size
                    if total > self.settings.max_uncompressed_bytes:
                        raise AuditServiceError("INVALID_EVIDENCE_BUNDLE", "Evidence bundle exceeds the uncompressed size limit.", 413)
                validated.append((name, info))
            if not REQUIRED_BUNDLE.issubset(names):
                raise AuditServiceError("INVALID_EVIDENCE_BUNDLE", "Evidence bundle is missing required root CSV files.", 400)
            return validated

    def _extract_and_validate_bundle(self, archive: bytes, destination: Path) -> list[dict[str, str]]:
        members = self._zip_members(archive)
        destination.mkdir(parents=True, exist_ok=True)
        root = destination.resolve()
        try:
            with zipfile.ZipFile(io.BytesIO(archive)) as zf:
                total_written = 0
                for name, info in members:
                    target = (root / Path(*PurePosixPath(name).parts)).resolve()
                    if not target.is_relative_to(root):
                        raise AuditServiceError("INVALID_EVIDENCE_BUNDLE", "Evidence bundle contains an unsafe path.", 400)
                    if info.is_dir():
                        target.mkdir(parents=True, exist_ok=True)
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    written = 0
                    with zf.open(info, "r") as source, target.open("xb") as sink:
                        while True:
                            block = source.read(1024 * 1024)
                            if not block:
                                break
                            written += len(block)
                            total_written += len(block)
                            if written > info.file_size or total_written > self.settings.max_uncompressed_bytes:
                                raise AuditServiceError("INVALID_EVIDENCE_BUNDLE", "Evidence bundle exceeded its declared size.", 413)
                            sink.write(block)
                    if written != info.file_size:
                        raise AuditServiceError("INVALID_EVIDENCE_BUNDLE", "Evidence bundle contains a truncated file.", 400)
            for required in REQUIRED_BUNDLE:
                if not (root / required).is_file():
                    raise AuditServiceError("INVALID_EVIDENCE_BUNDLE", "Evidence bundle is missing required root CSV files.", 400)
            with (root / "evidence_files.csv").open("r", encoding="utf-8-sig", newline="") as manifest_handle:
                manifest_reader = csv.DictReader(manifest_handle, strict=True)
                manifest_fields = manifest_reader.fieldnames or []
                manifest_header = set(manifest_fields)
                if (not {"file_id", "file_path", "captured_at"}.issubset(manifest_header) or
                        len(manifest_fields) != len(manifest_header) or any(not name.strip() for name in manifest_fields)):
                    raise AuditServiceError("INVALID_EVIDENCE_BUNDLE", "Evidence manifest is missing required or has duplicate columns.", 400)
                manifest = list(manifest_reader)
            file_ids = [str(row.get("file_id", "")).strip() for row in manifest]
            paths = [str(row.get("file_path", "")).replace("\\", "/") for row in manifest]
            captures = [str(row.get("captured_at", "")).strip() for row in manifest]
            if any(not value for value in file_ids + paths + captures) or len(file_ids) != len(set(file_ids)):
                raise AuditServiceError("INVALID_EVIDENCE_BUNDLE", "Evidence manifest contains missing or duplicate references.", 400)
            if any(core.parse_time(value) is None for value in captures):
                raise AuditServiceError("INVALID_EVIDENCE_BUNDLE", "Evidence manifest contains an invalid capture timestamp.", 400)
            member_names = {name for name, info in members if not info.is_dir()}
            for rel in paths:
                posix = PurePosixPath(rel)
                win = PureWindowsPath(rel)
                if win.is_absolute() or win.drive or any(part in {".", ".."} for part in posix.parts) or rel not in member_names:
                    raise AuditServiceError("INVALID_EVIDENCE_BUNDLE", "Evidence manifest references an invalid or missing file.", 400)
                if Path(rel).suffix.casefold() not in ALLOWED_EXTENSIONS:
                    raise AuditServiceError("UNSUPPORTED_FILE", "Evidence manifest references an unsupported file type.", 415)
            validate_manifest_paths(root, manifest)
            required_headers = {
                "user_identities.csv": {"user_id", "email", "updated_at"},
                "user_audit_log.csv": {"audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"},
                "system_activity.csv": {"activity_id", "event_time", "event_type", "resource_id"},
            }
            required_headers["deletion_rules.csv"] = {"data_category", "condition"}
            for name, required in required_headers.items():
                with (root / name).open("r", encoding="utf-8-sig", newline="") as handle:
                    reader = csv.DictReader(handle, strict=True)
                    fields = reader.fieldnames or []
                    if not required.issubset(set(fields)):
                        raise AuditServiceError("INVALID_EVIDENCE_BUNDLE", "A required bundle CSV is missing required columns.", 400)
                    list(reader)
                    if name == "deletion_rules.csv" and not ({"required_treatment", "required_action"} & set(fields)):
                        raise AuditServiceError("INVALID_EVIDENCE_BUNDLE", "Deletion rules are missing their required treatment column.", 400)
            return manifest
        except AuditServiceError:
            raise
        except (OSError, ValueError, csv.Error, zipfile.BadZipFile, RuntimeError):
            raise AuditServiceError("INVALID_EVIDENCE_BUNDLE", "Evidence bundle could not be safely extracted or validated.", 400) from None

    def validate_submission(self, request_data: bytes, archive: bytes) -> tuple[int, int]:
        self.cleanup_expired()
        if len(request_data) > self.settings.max_upload_bytes or len(archive) > self.settings.max_upload_bytes:
            raise AuditServiceError("INVALID_INPUT", "An uploaded file exceeds the upload size limit.", 413)
        rows = self.validate_requests(request_data)
        with tempfile.TemporaryDirectory(prefix="ghost-audit-validate-", dir=self.root) as temporary:
            manifest = self._extract_and_validate_bundle(archive, Path(temporary) / "bundle")
        return len(rows), len(manifest)

    def submit(self, request_data: bytes, archive: bytes) -> dict[str, Any]:
        self.cleanup_expired()
        if len(request_data) > self.settings.max_upload_bytes or len(archive) > self.settings.max_upload_bytes:
            raise AuditServiceError("INVALID_INPUT", "An uploaded file exceeds the upload size limit.", 413)
        rows = self.validate_requests(request_data)
        if not self._slots.acquire(blocking=False):
            raise AuditServiceError("CONCURRENCY_LIMIT", "The configured local audit capacity is busy.", 429)
        audit_id = uuid.uuid4().hex
        audit_dir = self._audit_dir(audit_id)
        created_at = datetime.now(timezone.utc).isoformat()
        metadata: dict[str, Any] = {"audit_id": audit_id, "created_at": created_at, "status": "RUNNING"}
        started = time.perf_counter()
        try:
            audit_dir.mkdir(parents=True, exist_ok=False)
            _restrict_directory(audit_dir)
            self._write_json(audit_dir / "metadata.json", metadata)
            request_path = audit_dir / "requests.csv"
            request_path.write_bytes(request_data)
            bundle_dir = audit_dir / "bundle"
            self._extract_and_validate_bundle(archive, bundle_dir)
            output_path = audit_dir / "output.csv"
            project_root = Path(__file__).resolve().parents[2]
            command = [sys.executable, "-m", "ghost_audit", "run", "--requests", str(request_path),
                       "--evidence-dir", str(bundle_dir), "--output", str(output_path)]
            try:
                completed = self._run_engine(command, project_root)
            except subprocess.TimeoutExpired:
                raise AuditServiceError("AUDIT_TIMEOUT", "Audit exceeded the configured execution timeout.", 504) from None
            if completed.returncode != 0:
                raise AuditServiceError("AUDIT_EXECUTION_FAILED", "The local audit engine could not complete this run.", 500)
            issues = validate_output_file(output_path, request_path)
            if issues:
                raise AuditServiceError("VALIDATION_FAILED", "Generated results failed output validation.", 500)
            with output_path.open("r", encoding="utf-8-sig", newline="") as handle:
                output_rows = list(csv.DictReader(handle))
            cases = []
            for row in output_rows:
                steps = json.loads(row["steps_json"])
                needs_review = row["deletion_status"] == "INCOMPLETE" and not steps
                cases.append({"case_id": row["case_id"], "deletion_status": row["deletion_status"],
                              "steps": steps, "review_label": "NEEDS_REVIEW" if needs_review else None})
            counts = {key: sum(c["deletion_status"] == key for c in cases)
                      for key in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE")}
            incomplete = counts["INCOMPLETE"]
            review_count = sum(c["review_label"] == "NEEDS_REVIEW" for c in cases)
            duration = round(time.perf_counter() - started, 3)
            summary = {"audit_id": audit_id, "created_at": created_at, "status": "COMPLETED",
                       "request_count": len(rows), "status_counts": counts, "duration_seconds": duration,
                       "validation_status": "PASSED", "needs_review_count": review_count,
                       "needs_review_percent_of_incomplete": round(100 * review_count / incomplete, 2) if incomplete else 0.0}
            self._write_json(audit_dir / "cases.json", cases)
            metadata = {"audit_id": audit_id, "created_at": created_at, "status": "COMPLETED", "summary": summary}
            self._write_json(audit_dir / "metadata.json", metadata)
            return summary
        except AuditServiceError as exc:
            if audit_dir.is_dir():
                self._mark_failed(audit_dir, metadata, exc.code)
            raise
        except Exception:
            if audit_dir.is_dir():
                self._mark_failed(audit_dir, metadata, "AUDIT_EXECUTION_FAILED")
            raise AuditServiceError("AUDIT_EXECUTION_FAILED", "The local audit could not be completed.", 500) from None
        finally:
            self._slots.release()

    def _run_engine(self, command: list[str], project_root: Path) -> subprocess.CompletedProcess:
        kwargs = {"cwd": project_root, "capture_output": True, "text": True,
                  "timeout": self.settings.execution_timeout_seconds, "check": False}
        if self.runner is not None:
            return self.runner(command, **kwargs)
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
        process = subprocess.Popen(
            command, cwd=project_root, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            creationflags=creationflags, start_new_session=(os.name != "nt"),
        )
        try:
            stdout, stderr = process.communicate(timeout=self.settings.execution_timeout_seconds)
        except subprocess.TimeoutExpired:
            self._terminate_process_tree(process)
            raise subprocess.TimeoutExpired(command, self.settings.execution_timeout_seconds) from None
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)

    @staticmethod
    def _terminate_process_tree(process: subprocess.Popen) -> None:
        if os.name == "nt":
            try:
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=5, check=False,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            except Exception:
                try:
                    process.kill()
                except OSError:
                    pass
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                except OSError:
                    pass
                process.communicate()
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()

    def _mark_failed(self, audit_dir: Path, metadata: dict[str, Any], error_code: str) -> None:
        for name in ("requests.csv", "bundle", "output.csv", "cases.json"):
            path = audit_dir / name
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
            elif path.exists():
                try: path.unlink()
                except OSError: pass
        metadata.update({"status": "FAILED", "error_code": error_code})
        try:
            self._write_json(audit_dir / "metadata.json", metadata)
        except OSError:
            pass

    def get_audit(self, audit_id: str) -> dict[str, Any]:
        self.cleanup_expired()
        path = self._audit_dir(audit_id) / "metadata.json"
        if not path.is_file():
            raise AuditServiceError("AUDIT_NOT_FOUND", "Audit was not found.", 404)
        data = self._read_json(path)
        return data

    def get_cases(self, audit_id: str, status: str | None, offset: int, limit: int,
                  sort_by: str = "case_id", order: str = "asc") -> dict[str, Any]:
        directory = self._audit_dir(audit_id)
        self.get_audit(audit_id)
        path = directory / "cases.json"
        if not path.is_file():
            raise AuditServiceError("AUDIT_NOT_FOUND", "Completed audit results are unavailable.", 404)
        cases = self._read_json(path)
        if status:
            cases = [case for case in cases if case["deletion_status"] == status]
        def case_key(case: dict[str, Any]):
            case_id = case["case_id"]
            suffix = case_id.rsplit("_", 1)[-1]
            numeric_id = (0, int(suffix)) if suffix.isdigit() else (1, case_id.casefold())
            if sort_by == "deletion_status":
                ranks = {"COMPLETE": 0, "INCOMPLETE": 1, "NOT_APPLICABLE": 2}
                return (ranks[case["deletion_status"]], numeric_id)
            return numeric_id
        cases.sort(key=case_key, reverse=(order == "desc"))
        return {"items": cases[offset:offset + limit], "total": len(cases), "offset": offset, "limit": limit}

    def get_case(self, audit_id: str, case_id: str) -> dict[str, Any]:
        result = self.get_cases(audit_id, None, 0, 100000)
        for case in result["items"]:
            if case["case_id"] == case_id:
                return {**case, "evidence_references": sorted({s["evidence_id"] for s in case["steps"] if s.get("evidence_id")})}
        raise AuditServiceError("CASE_NOT_FOUND", "Case was not found in this audit.", 404)

    def download_path(self, audit_id: str) -> Path:
        self.get_audit(audit_id)
        path = self._audit_dir(audit_id) / "output.csv"
        if not path.is_file():
            raise AuditServiceError("AUDIT_NOT_FOUND", "Completed audit output is unavailable.", 404)
        return path

    def preview(self, audit_id: str, evidence_id: str, max_chars: int = 4000) -> dict[str, Any]:
        directory = self._audit_dir(audit_id)
        self.get_audit(audit_id)
        bundle = directory / "bundle"
        if not bundle.is_dir():
            raise AuditServiceError("AUDIT_NOT_FOUND", "Retained evidence bundle is unavailable.", 404)
        manifest = core.read_csv(bundle / "evidence_files.csv")
        entries = [row for row in manifest if row.get("file_id") == evidence_id]
        if len(entries) != 1:
            return {"evidence_id": evidence_id, "available": False, "message": "This reference is not a uniquely mapped evidence file."}
        rel = entries[0].get("file_path", "")
        source = (bundle / rel).resolve()
        if not source.is_relative_to(bundle.resolve()) or not source.is_file():
            return {"evidence_id": evidence_id, "available": False, "message": "Evidence preview is unavailable for this reference."}
        stat_result = source.stat()
        key = (audit_id, evidence_id, stat_result.st_mtime_ns, stat_result.st_size)
        if key in self._preview_cache:
            text = self._preview_cache[key]
        else:
            text = self._extract_preview(bundle, source, evidence_id)
            self._preview_cache[key] = text
        if not text:
            return {"evidence_id": evidence_id, "source_file": rel, "available": False,
                    "message": "A safe text preview is unavailable for this evidence format or content."}
        return {"evidence_id": evidence_id, "source_file": rel, "available": True,
                "excerpt": text[:max_chars], "truncated": len(text) > max_chars}

    @staticmethod
    def _extract_preview(bundle: Path, source: Path, evidence_id: str) -> str:
        ext = source.suffix.casefold()
        try:
            if ext in {".txt", ".log", ".json", ".csv", ".sql"}:
                with source.open("rb") as handle:
                    raw = handle.read(64 * 1024 + 1)
                return raw[:64 * 1024].decode("utf-8-sig", errors="replace")
            if ext == ".pdf":
                if source.stat().st_size > 10 * 1024 * 1024:
                    return ""
                from pypdf import PdfReader  # type: ignore
                return "\n\n".join(page.extract_text() or "" for page in PdfReader(str(source)).pages)
            if ext in {".png", ".jpg", ".jpeg"}:
                # Reuse the engine's bounded local OCR for this one validated image;
                # do not rebuild or rescan the entire evidence index for a preview.
                index = object.__new__(core.EvidenceIndex)
                index._ocr_engine_checked = False
                index._ocr_engine_available = False
                index._ocr_command_checked = False
                index._ocr_command = ""
                return index._image_text(source)
        except Exception:
            return ""
        return ""

    def delete_audit(self, audit_id: str) -> None:
        directory = self._audit_dir(audit_id)
        self.get_audit(audit_id)
        shutil.rmtree(directory)
        self._preview_cache = {key: value for key, value in self._preview_cache.items() if key[0] != audit_id}

    def cleanup_expired(self, now: datetime | None = None) -> int:
        now = now or datetime.now(timezone.utc)
        removed = 0
        if not self.root.is_dir():
            return removed
        for directory in self.root.iterdir():
            if not directory.is_dir() or not AUDIT_ID_RE.fullmatch(directory.name):
                continue
            meta = directory / "metadata.json"
            try:
                data = self._read_json(meta)
                created = datetime.fromisoformat(data["created_at"].replace("Z", "+00:00"))
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                if (now - created).total_seconds() >= self.settings.retention_hours * 3600:
                    shutil.rmtree(directory)
                    removed += 1
            except (OSError, ValueError, KeyError, json.JSONDecodeError):
                continue
        if removed:
            self._preview_cache = {key: value for key, value in self._preview_cache.items()
                                   if (self.root / key[0]).exists()}
        return removed

    @staticmethod
    def _write_json(path: Path, value: Any) -> None:
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
        os.replace(temporary, path)

    @staticmethod
    def _read_json(path: Path) -> Any:
        return json.loads(path.read_text(encoding="utf-8"))


def _restrict_directory(path: Path) -> None:
    if os.name != "nt":
        try: path.chmod(0o700)
        except OSError: pass
