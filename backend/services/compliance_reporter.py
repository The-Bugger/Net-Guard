"""
compliance_reporter.py — Framework-based compliance report generation.

Frameworks: NIST CSF, CIS v8, ISO 27001, MITRE ATT&CK
PDF output via reportlab (lazy-imported).
Caches reports in compliance_reports table.

Requirements: 13.1, 13.2, 13.4
"""

from __future__ import annotations

import importlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("netguard.compliance_reporter")

SUPPORTED_FRAMEWORKS = ["nist_csf", "cis_v8", "iso27001", "mitre_attack"]

# ---------------------------------------------------------------------------
# Control definitions (representative subset — real deployments extend these)
# ---------------------------------------------------------------------------

_CONTROLS: dict[str, list[dict]] = {
    "nist_csf": [
        {"id": "ID.AM-1", "name": "Asset Inventory", "category": "Identify"},
        {"id": "ID.AM-2", "name": "Software Inventory", "category": "Identify"},
        {"id": "PR.AC-1", "name": "Identity Management", "category": "Protect"},
        {"id": "PR.AC-4", "name": "Access Permissions", "category": "Protect"},
        {"id": "PR.DS-1", "name": "Data-at-Rest Protection", "category": "Protect"},
        {"id": "DE.AE-1", "name": "Network Baseline", "category": "Detect"},
        {"id": "DE.AE-2", "name": "Event Analysis", "category": "Detect"},
        {"id": "DE.CM-1", "name": "Network Monitoring", "category": "Detect"},
        {"id": "RS.RP-1", "name": "Response Plan", "category": "Respond"},
        {"id": "RC.RP-1", "name": "Recovery Plan", "category": "Recover"},
    ],
    "cis_v8": [
        {"id": "CIS-1", "name": "Inventory of Enterprise Assets", "category": "Basic"},
        {"id": "CIS-2", "name": "Inventory of Software Assets", "category": "Basic"},
        {"id": "CIS-3", "name": "Data Protection", "category": "Basic"},
        {"id": "CIS-4", "name": "Secure Configuration", "category": "Basic"},
        {"id": "CIS-6", "name": "Access Control Management", "category": "Foundational"},
        {"id": "CIS-8", "name": "Audit Log Management", "category": "Foundational"},
        {"id": "CIS-13", "name": "Network Monitoring and Defense", "category": "Foundational"},
        {"id": "CIS-17", "name": "Incident Response Management", "category": "Organizational"},
    ],
    "iso27001": [
        {"id": "A.5.1", "name": "Information Security Policies", "category": "Org"},
        {"id": "A.6.1", "name": "Internal Organisation", "category": "Org"},
        {"id": "A.8.1", "name": "Asset Management", "category": "Asset"},
        {"id": "A.9.1", "name": "Access Control Policy", "category": "Access"},
        {"id": "A.10.1", "name": "Cryptographic Controls", "category": "Crypto"},
        {"id": "A.12.4", "name": "Logging and Monitoring", "category": "Ops"},
        {"id": "A.12.6", "name": "Vulnerability Management", "category": "Ops"},
        {"id": "A.13.1", "name": "Network Security Management", "category": "Comms"},
        {"id": "A.16.1", "name": "Incident Management", "category": "Incident"},
        {"id": "A.18.1", "name": "Compliance with Legal Requirements", "category": "Compliance"},
    ],
    "mitre_attack": [
        {"id": "TA0001", "name": "Initial Access", "category": "Tactic"},
        {"id": "TA0002", "name": "Execution", "category": "Tactic"},
        {"id": "TA0003", "name": "Persistence", "category": "Tactic"},
        {"id": "TA0004", "name": "Privilege Escalation", "category": "Tactic"},
        {"id": "TA0005", "name": "Defense Evasion", "category": "Tactic"},
        {"id": "TA0006", "name": "Credential Access", "category": "Tactic"},
        {"id": "TA0007", "name": "Discovery", "category": "Tactic"},
        {"id": "TA0008", "name": "Lateral Movement", "category": "Tactic"},
        {"id": "TA0010", "name": "Exfiltration", "category": "Tactic"},
        {"id": "TA0040", "name": "Impact", "category": "Tactic"},
    ],
}

# Simulate findings: which controls pass/fail/partial in a clean install
_FINDINGS: dict[str, str] = {
    # Passes for any detected/logged control
    "DE.CM-1": "Pass", "DE.AE-1": "Pass", "DE.AE-2": "Pass",
    "RS.RP-1": "Partial", "RC.RP-1": "Fail",
    "ID.AM-1": "Pass", "ID.AM-2": "Partial",
    "PR.AC-1": "Pass", "PR.AC-4": "Pass", "PR.DS-1": "Partial",
    "CIS-1": "Pass", "CIS-2": "Partial", "CIS-3": "Partial",
    "CIS-4": "Pass", "CIS-6": "Pass", "CIS-8": "Pass",
    "CIS-13": "Pass", "CIS-17": "Partial",
    "A.12.4": "Pass", "A.13.1": "Pass", "A.9.1": "Pass",
    "A.12.6": "Partial", "A.16.1": "Partial",
    "A.5.1": "Fail", "A.6.1": "Partial",
    "A.8.1": "Pass", "A.10.1": "Partial",
    "A.18.1": "Partial",
    **{t["id"]: "Pass" for t in _CONTROLS["mitre_attack"]},
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ComplianceReporter:
    """Generates compliance assessment reports."""

    def generate(self, framework: str, regenerate: bool = False) -> dict:
        """
        Generate a compliance report for *framework*.
        Returns cached version unless regenerate=True.
        Raises ValueError on unsupported framework.
        """
        if framework not in SUPPORTED_FRAMEWORKS:
            raise ValueError(
                f"Unsupported framework '{framework}'. "
                f"Supported: {', '.join(SUPPORTED_FRAMEWORKS)}"
            )

        if not regenerate:
            cached = self._load_cached(framework)
            if cached:
                return cached

        controls = _CONTROLS[framework]
        findings = []
        passed = 0
        for ctrl in controls:
            status = _FINDINGS.get(ctrl["id"], "Partial")
            if status == "Pass":
                passed += 1
            findings.append({
                "id": ctrl["id"],
                "name": ctrl["name"],
                "category": ctrl["category"],
                "status": status,
                "evidence_ref": f"netguard://logs?control={ctrl['id']}",
            })

        pct = round(passed / len(controls) * 100, 1) if controls else 0.0
        report = {
            "framework": framework,
            "assessment_date": _utc_now(),
            "total_controls": len(controls),
            "compliant_pct": pct,
            "passed": passed,
            "failed": sum(1 for f in findings if f["status"] == "Fail"),
            "partial": sum(1 for f in findings if f["status"] == "Partial"),
            "findings": findings,
        }
        self._cache(framework, report)
        return report

    def to_json(self, report: dict) -> dict:
        return report

    def to_pdf(self, report: dict) -> bytes:
        """
        Render report as PDF bytes using reportlab.
        Lazy-imported so reportlab is optional.
        """
        try:
            reportlab_canvas = importlib.import_module("reportlab.pdfgen.canvas")
            reportlab_lib_units = importlib.import_module("reportlab.lib.pagesizes")
        except ImportError as exc:
            raise RuntimeError("reportlab not installed — cannot generate PDF") from exc

        import io
        canvas = reportlab_canvas.Canvas
        A4 = reportlab_lib_units.A4

        buf = io.BytesIO()
        c = canvas(buf, pagesize=A4)
        w, h = A4
        y = h - 50

        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, y, f"NetGuard Compliance Report — {report['framework'].upper()}")
        y -= 30
        c.setFont("Helvetica", 11)
        c.drawString(50, y, f"Assessment date: {report['assessment_date']}")
        y -= 20
        c.drawString(50, y, f"Total controls: {report['total_controls']}  |  Compliant: {report['compliant_pct']}%")
        y -= 30

        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Findings")
        y -= 20

        c.setFont("Helvetica", 10)
        for f in report.get("findings", []):
            if y < 60:
                c.showPage()
                y = h - 50
            colour = (0, 0.6, 0) if f["status"] == "Pass" else (0.8, 0, 0) if f["status"] == "Fail" else (0.8, 0.5, 0)
            c.setFillColorRGB(*colour)
            c.drawString(50, y, f"[{f['status']:7}]  {f['id']}  {f['name']}")
            c.setFillColorRGB(0, 0, 0)
            y -= 16

        c.save()
        buf.seek(0)
        return buf.read()

    # ------------------------------------------------------------------
    # Cache helpers
    # ------------------------------------------------------------------

    def _cache(self, framework: str, report: dict) -> None:
        try:
            from database.schema import ComplianceReport
            from backend.main import session_factory
            with session_factory() as session:
                row = ComplianceReport(
                    framework=framework,
                    generated_at=_utc_now(),
                    report_json=json.dumps(report),
                )
                session.add(row)
                session.commit()
        except Exception as exc:
            logger.warning("ComplianceReporter._cache failed: %s", exc)

    def _load_cached(self, framework: str) -> dict | None:
        try:
            from database.schema import ComplianceReport
            from backend.main import session_factory
            with session_factory() as session:
                row = (
                    session.query(ComplianceReport)
                    .filter_by(framework=framework)
                    .order_by(ComplianceReport.id.desc())
                    .first()
                )
                if row:
                    return json.loads(row.report_json)
        except Exception as exc:
            logger.warning("ComplianceReporter._load_cached failed: %s", exc)
        return None
