"""
reports_routes.py — Compliance report endpoints.

GET /api/v1/reports/compliance?framework={name}&regenerate={bool}&format={json|pdf}

Requirements: 13.1, 13.2, 13.4
"""

from flask import Blueprint, request, Response
from backend.api import dependencies
from backend.middleware.auth_middleware import require_role
from backend.utils.response import success_response, error_response
from backend.services.compliance_reporter import SUPPORTED_FRAMEWORKS

reports_bp = Blueprint("reports", __name__)


@reports_bp.get("/reports/compliance")
@require_role("admin", "analyst", "hunter", "viewer")
def get_compliance_report():
    framework = request.args.get("framework", "").strip().lower()
    if not framework:
        return error_response(
            f"framework required. Supported: {', '.join(SUPPORTED_FRAMEWORKS)}", 400
        )

    regenerate = request.args.get("regenerate", "false").lower() == "true"
    fmt = request.args.get("format", "json").lower()

    reporter = dependencies.get("compliance_reporter")
    if not reporter:
        return error_response("Compliance reporter not available", 503)

    try:
        report = reporter.generate(framework, regenerate=regenerate)
    except ValueError as exc:
        return error_response(str(exc), 400, "UNSUPPORTED_FRAMEWORK")

    if fmt == "pdf":
        try:
            pdf_bytes = reporter.to_pdf(report)
            return Response(
                pdf_bytes,
                mimetype="application/pdf",
                headers={
                    "Content-Disposition": f"attachment; filename=netguard_compliance_{framework}.pdf"
                },
            )
        except RuntimeError as exc:
            return error_response(str(exc), 503, "PDF_UNAVAILABLE")

    return success_response(reporter.to_json(report))
