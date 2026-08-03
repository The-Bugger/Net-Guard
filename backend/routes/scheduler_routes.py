"""
scheduler_routes.py — Attack scheduler REST API.

POST /api/v1/scheduler/jobs
POST /api/v1/scheduler/jobs/batch
GET  /api/v1/scheduler/jobs
DELETE /api/v1/scheduler/jobs/{id}

Requirements: 2.1, 2.6, 2.7, 2.10
"""

from flask import Blueprint, request
from backend.api import dependencies
from backend.middleware.auth_middleware import require_role
from backend.utils.response import success_response, error_response, created_response

scheduler_bp = Blueprint("scheduler", __name__)


def _svc():
    return dependencies.get("scheduler_service")


def _unavailable():
    return error_response("Scheduler service unavailable", 503)


@scheduler_bp.post("/scheduler/jobs")
@require_role("admin", "analyst")
def create_job():
    if _svc() is None:
        return _unavailable()
    config = request.get_json(silent=True) or {}
    try:
        result = _svc().create_job(config)
        return created_response(result, "Job scheduled")
    except ValueError as exc:
        return error_response(str(exc), 400)


@scheduler_bp.post("/scheduler/jobs/batch")
@require_role("admin", "analyst")
def create_batch():
    if _svc() is None:
        return _unavailable()
    data = request.get_json(silent=True) or {}
    configs = data.get("jobs", [])
    try:
        result = _svc().create_batch(configs)
        return created_response(result, "Batch scheduled")
    except ValueError as exc:
        code = str(exc)
        if "BATCH_LIMIT_EXCEEDED" in code:
            return error_response("Batch exceeds 50 job limit", 400, "BATCH_LIMIT_EXCEEDED")
        return error_response(code, 400)


@scheduler_bp.get("/scheduler/jobs")
@require_role("admin", "analyst", "hunter", "viewer")
def list_jobs():
    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(100, max(1, int(request.args.get("per_page", 20))))
    except (ValueError, TypeError):
        return error_response("Invalid pagination", 400)

    status = request.args.get("status")
    attack_type = request.args.get("attack_type")
    if _svc() is None:
        return _unavailable()
    result = _svc().list_jobs(page=page, per_page=per_page, status=status, attack_type=attack_type)
    return success_response(result)


@scheduler_bp.delete("/scheduler/jobs/<job_id>")
@require_role("admin", "analyst")
def cancel_job(job_id: str):
    if _svc() is None:
        return _unavailable()
    ok = _svc().cancel_job(job_id)
    if not ok:
        return error_response("Job not found", 404)
    return success_response(None, "Job cancelled")
