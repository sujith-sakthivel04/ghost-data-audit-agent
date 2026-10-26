"""Typed local-only FastAPI interface for the Ghost Data Audit engine."""
from __future__ import annotations

from contextlib import asynccontextmanager
import hmac
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, File, Header, Query, UploadFile
from fastapi.exceptions import RequestValidationError
from starlette.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from . import __version__
from .service import AppSettings, AuditService, AuditServiceError


class AuthenticationError(Exception):
    """Raised for missing or invalid bearer credentials without echoing values."""


class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorDetail


class HealthResponse(BaseModel):
    status: Literal["ok"]
    engine_available: bool
    implementation_mode: Literal["deterministic_local"]


class VersionResponse(BaseModel):
    version: str
    implementation_mode: Literal["deterministic_local"]
    hosted_model_calls: Literal[False]
    retention_hours: int


class AuditSummary(BaseModel):
    audit_id: str
    created_at: str
    status: str
    request_count: int
    status_counts: dict[str, int]
    duration_seconds: float
    validation_status: str
    needs_review_count: int
    needs_review_percent_of_incomplete: float


class AuditAccepted(BaseModel):
    audit_id: str
    summary: AuditSummary


class CaseResult(BaseModel):
    case_id: str
    deletion_status: Literal["COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"]
    steps: list[dict[str, Any]]
    review_label: str | None = None


class CasePage(BaseModel):
    items: list[CaseResult]
    total: int
    offset: int
    limit: int


class CaseDetail(CaseResult):
    evidence_references: list[str] = Field(default_factory=list)


class PreviewResponse(BaseModel):
    evidence_id: str
    source_file: str | None = None
    available: bool
    excerpt: str | None = None
    truncated: bool = False
    message: str | None = None


class ValidationResponse(BaseModel):
    valid: Literal[True]
    request_count: int
    manifest_file_count: int
    local_processing: Literal[True]


ERROR_RESPONSES = {
    401: {"model": ErrorResponse, "description": "Bearer authentication required or invalid."},
    400: {"model": ErrorResponse, "description": "Invalid request or bundle."},
    404: {"model": ErrorResponse, "description": "Audit or case not found."},
    413: {"model": ErrorResponse, "description": "Configured size or resource limit exceeded."},
    415: {"model": ErrorResponse, "description": "Unsupported upload type."},
    429: {"model": ErrorResponse, "description": "Local audit capacity is busy."},
    500: {"model": ErrorResponse, "description": "Execution or result validation failed."},
    504: {"model": ErrorResponse, "description": "Configured execution timeout reached."},
}


def create_app(settings: AppSettings | None = None, service: AuditService | None = None) -> FastAPI:
    settings = settings or AppSettings.from_env()
    settings.validate_security()
    audit_service = service or AuditService(settings)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        audit_service.cleanup_expired()
        yield

    app = FastAPI(title="Ghost Data Audit", version=__version__, lifespan=lifespan,
                  docs_url=None if settings.mode == "production" else "/docs",
                  redoc_url=None if settings.mode == "production" else "/redoc",
                  openapi_url=None if settings.mode == "production" else "/openapi.json")
    app.state.audit_service = audit_service
    if settings.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins),
                           allow_credentials=False, allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
                           allow_headers=["Authorization", "Content-Type"], max_age=300)

    async def require_auth(authorization: str | None = Header(default=None)) -> None:
        if not settings.authentication_enabled:
            return
        parts = authorization.split() if authorization else []
        supplied = parts[1] if len(parts) == 2 and parts[0].casefold() == "bearer" else ""
        expected = settings.bearer_token or ""
        if not supplied or not hmac.compare_digest(supplied, expected):
            raise AuthenticationError()

    @app.exception_handler(AuditServiceError)
    async def service_error_handler(_request, exc: AuditServiceError):
        return JSONResponse(status_code=exc.status_code, content={"error": {"code": exc.code, "message": exc.message}})

    @app.exception_handler(AuthenticationError)
    async def authentication_error_handler(_request, _exc: AuthenticationError):
        return JSONResponse(status_code=401,
                            headers={"WWW-Authenticate": "Bearer"},
                            content={"error": {"code": "AUTHENTICATION_REQUIRED",
                                                "message": "A valid bearer token is required."}})

    @app.exception_handler(RequestValidationError)
    async def request_error_handler(_request, _exc: RequestValidationError):
        return JSONResponse(status_code=400, content={"error": {"code": "INVALID_INPUT", "message": "Request parameters or uploaded fields are invalid."}})

    @app.get("/api/health", response_model=HealthResponse)
    def health():
        return {"status": "ok", "engine_available": True, "implementation_mode": "deterministic_local"}

    @app.get("/api/version", response_model=VersionResponse)
    def version():
        return {"version": __version__, "implementation_mode": "deterministic_local",
                "hosted_model_calls": False, "retention_hours": settings.retention_hours}

    async def read_upload(file: UploadFile, expected_suffix: str) -> bytes:
        name = (file.filename or "").casefold()
        if not name.endswith(expected_suffix):
            raise AuditServiceError("UNSUPPORTED_FILE", f"Upload must be a {expected_suffix} file.", 415)
        data = await file.read(settings.max_upload_bytes + 1)
        if len(data) > settings.max_upload_bytes:
            raise AuditServiceError("INVALID_INPUT", "An uploaded file exceeds the upload size limit.", 413)
        return data

    @app.post("/api/validate", response_model=ValidationResponse, responses=ERROR_RESPONSES, dependencies=[Depends(require_auth)])
    async def validate_inputs(request_csv: UploadFile = File(...), evidence_bundle: UploadFile = File(...)):
        requests_data = await read_upload(request_csv, ".csv")
        bundle_data = await read_upload(evidence_bundle, ".zip")
        request_count, manifest_count = await run_in_threadpool(audit_service.validate_submission, requests_data, bundle_data)
        return {"valid": True, "request_count": request_count, "manifest_file_count": manifest_count, "local_processing": True}

    @app.post("/api/audits", response_model=AuditAccepted, status_code=201, responses=ERROR_RESPONSES, dependencies=[Depends(require_auth)])
    async def create_audit(request_csv: UploadFile = File(...), evidence_bundle: UploadFile = File(...)):
        requests_data = await read_upload(request_csv, ".csv")
        bundle_data = await read_upload(evidence_bundle, ".zip")
        summary = await run_in_threadpool(audit_service.submit, requests_data, bundle_data)
        return {"audit_id": summary["audit_id"], "summary": summary}

    @app.get("/api/audits/{audit_id}", responses=ERROR_RESPONSES, dependencies=[Depends(require_auth)])
    def get_audit(audit_id: str):
        result = audit_service.get_audit(audit_id)
        return result

    @app.get("/api/audits/{audit_id}/cases", response_model=CasePage, responses=ERROR_RESPONSES, dependencies=[Depends(require_auth)])
    def get_cases(audit_id: str, status: Literal["COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"] | None = None,
                  offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500),
                  sort_by: Literal["case_id", "deletion_status"] = "case_id",
                  order: Literal["asc", "desc"] = "asc"):
        return audit_service.get_cases(audit_id, status, offset, limit, sort_by, order)

    @app.get("/api/audits/{audit_id}/cases/{case_id}", response_model=CaseDetail, responses=ERROR_RESPONSES, dependencies=[Depends(require_auth)])
    def get_case(audit_id: str, case_id: str):
        return audit_service.get_case(audit_id, case_id)

    @app.get("/api/audits/{audit_id}/evidence/{evidence_id}/preview", response_model=PreviewResponse, responses=ERROR_RESPONSES, dependencies=[Depends(require_auth)])
    def evidence_preview(audit_id: str, evidence_id: str):
        return audit_service.preview(audit_id, evidence_id)

    @app.get("/api/audits/{audit_id}/download", responses=ERROR_RESPONSES, dependencies=[Depends(require_auth)])
    def download_csv(audit_id: str):
        return FileResponse(audit_service.download_path(audit_id), media_type="text/csv", filename="ghost_audit_output.csv")

    @app.get("/api/audits/{audit_id}/detail.json", responses=ERROR_RESPONSES, dependencies=[Depends(require_auth)])
    def download_detail(audit_id: str):
        summary = audit_service.get_audit(audit_id)
        result = audit_service.get_cases(audit_id, None, 0, 100000)
        return {"summary": summary.get("summary", summary), "cases": result["items"]}

    @app.delete("/api/audits/{audit_id}", responses=ERROR_RESPONSES, dependencies=[Depends(require_auth)])
    def delete_audit(audit_id: str):
        audit_service.delete_audit(audit_id)
        return {"audit_id": audit_id, "deleted": True}

    return app
