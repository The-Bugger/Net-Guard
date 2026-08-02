"""
reports_routes.py — Compliance report endpoints.

GET /api/v1/reports/compliance?framework={name}&regenerate={bool}
GET /api/v1/reports/compliance/download?framework={name}&format={pdf|json}

Requirements: 13.1–13.5
"""

from flask import Blueprint, request, Response
from backend.api import dependencies
from backend.middleware.auth_middleware import require_role
from backend.utils.response import success_response, error_response
from backend.services.compliance_reporter import SUPPORTED_FRAMEWORKS

reports_bp = Blueprint("reports", __name__)


def _get_reporter():
    reporter = dependencies.get("compliance_reporter")
    if reporter is None:
        return None, error_response("Compliance reporter not available", 503)
    return reporter, None


def _validate_framework(framework: str):
    if not framework:
        return None, error_response(
            f"framework required. Supported: {', '.join(SUPPORTED_FRAMEWORKS)}", 400
        )
    if framework not in SUPPORTED_FRAMEWORKS:
        return None, error_response(
            f"Unsupported framework '{framework}'. Supported: {', '.join(SUPPORTED_FRAMEWORKS)}",
            400,
            "UNSUPPORTED_FRAMEWORK",
        )
    return framework, None


@reports_bp.get("/reports/compliance")
@require_role("admin", "analyst", "hunter", "viewer")
def get_compliance_report():
    """Return compliance report as JSON (Req 13.4)."""
    framework, err = _validate_framework(request.args.get("framework", "").strip().lower())
    if err:
        return err

    regenerate = request.args.get("regenerate", "false").lower() == "true"

    reporter, err = _get_reporter()
    if err:
        return err

    try:
        report = reporter.generate(framework, regenerate=regenerate)
    except ValueError as exc:
        return error_response(str(exc), 400, "UNSUPPORTED_FRAMEWORK")

    payload = reporter.to_json(report)
    # Normalise to the specified response shape
    return success_response({
        "framework": payload.get("framework", framework),
        "last_generated": payload.get("assessment_date"),
        "report": {
            "controls_evaluated": payload.get("total_controls", 0),
            "percent_compliant": payload.get("compliant_pct", 0.0),
            "findings": payload.get("findings", []),
        },
    })


@reports_bp.get("/reports/compliance/download")
@require_role("admin", "analyst")
def download_compliance_report():
    """Download compliance report as PDF or JSON attachment (Req 13.5)."""
    framework, err = _validate_framework(request.args.get("framework", "").strip().lower())
    if err:
        return err

    fmt = request.args.get("format", "json").lower()
    if fmt not in ("pdf", "json"):
        return error_response("format must be 'pdf' or 'json'", 400, "INVALID_FORMAT")

    reporter, err = _get_reporter()
    if err:
        return err

    try:
        report = reporter.generate(framework)
    except ValueError as exc:
        return error_response(str(exc), 400, "UNSUPPORTED_FRAMEWORK")

    if fmt == "pdf":
        try:
            data = reporter.to_pdf(report)
        except RuntimeError as exc:
            return error_response(str(exc), 503, "PDF_UNAVAILABLE")
        return Response(
            data,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=netguard_compliance_{framework}.pdf"},
        )

    # JSON download
    import json
    data = json.dumps(reporter.to_json(report), indent=2).encode()
    return Response(
        data,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=netguard_compliance_{framework}.json"},
    )
