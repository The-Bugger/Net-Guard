"""
export_routes.py — Export endpoint.

GET /export?format=<json|csv|markdown|pdf>[&severity=...&attack_type=...&source_ip=...&date=...&search=...]

Requirements: 6.1, 6.2, 6.3, 6.4, 6.6, 6.7
"""

from __future__ import annotations

from flask import Blueprint, request, Response

from backend.api.dependencies import get_event_repo
from backend.services.export_service import ExportService
from backend.utils.response import error_response

export_bp = Blueprint("export", __name__)

_CONTENT_TYPES = {
    "json":     "application/json",
    "csv":      "text/csv",
    "markdown": "text/markdown",
    "pdf":      "application/pdf",
}

_FILTER_PARAMS = ("severity", "attack_type", "source_ip", "date", "search")


@export_bp.get("/export")
def export_data():
    repo = get_event_repo()
    if repo is None:
        return error_response("Event repository unavailable.", 500, "SERVICE_UNAVAILABLE")

    fmt = request.args.get("format", "").lower()
    if fmt not in _CONTENT_TYPES:
        return error_response(f"Unknown export format: {fmt!r}.", 400, "INVALID_EXPORT_FORMAT")

    filters = {k: v for k in _FILTER_PARAMS if (v := request.args.get(k))}

    svc = ExportService(repo)

    try:
        if fmt == "json":
            data, filename = svc.export_json(filters)
        elif fmt == "csv":
            data, filename = svc.export_csv(filters)
            data = data.encode()
        elif fmt == "markdown":
            data, filename = svc.export_markdown(filters)
            data = data.encode()
        else:  # pdf
            data, filename = svc.export_pdf(filters)
    except ImportError:
        return error_response("PDF export requires reportlab or weasyprint.", 501, "PDF_NOT_SUPPORTED")

    return Response(
        data,
        mimetype=_CONTENT_TYPES[fmt],
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
