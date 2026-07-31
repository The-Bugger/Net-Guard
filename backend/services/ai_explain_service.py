"""
ai_explain_service.py — AI-powered explanation enrichment for NetGuard.

Provider-abstracted LLM service. Three providers selected via AI_PROVIDER env var:
  - "stub"   (default) — deterministic template, no network call, < 100ms
  - "gemini" — google-generativeai (optional extra, falls back to stub)
  - "openai" — openai ChatCompletion (optional extra, falls back to stub)

Uses collections.OrderedDict as an LRU cache (100 entries, keyed by event_id).

Requirements: 2.1, 2.4, 2.9, 2.10
"""

from __future__ import annotations

import logging
import os
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("netguard.ai_explain_service")

# All 7 required section headers for markdown_report (Req 2.4)
_REQUIRED_HEADERS = [
    "## Summary",
    "## Business Impact",
    "## How the Attacker Works",
    "## Immediate Actions",
    "## Long-term Recommendations",
    "## MITRE ATT&CK",
    "## CVE References",
]


@dataclass
class AIExplanation:
    """AI-enriched explanation for a ThreatEvent."""

    attack_name: str
    severity: str
    confidence_pct: int
    description: str
    business_impact: str
    attacker_methodology: str
    immediate_actions: list  # list[str] — never None
    long_term_recommendations: list  # list[str] — never None
    mitre_attack_mapping: list  # list[str] — never None
    cve_references: list  # list[str] — never None
    markdown_report: str  # non-empty, contains all 7 section headers
    is_fallback: bool = False


class AIExplainService:
    """
    Generate AI-enriched explanations for threat events.

    Raises ValueError immediately if either argument to generate() is None.
    Returns cached result on repeat calls for the same event_id.
    Falls back to stub on any provider error.
    """

    _CACHE_SIZE = 100

    def __init__(self) -> None:
        self._provider: str = os.environ.get("AI_PROVIDER", "stub").lower()
        self._cache: OrderedDict = OrderedDict()
        self._lock = threading.Lock()

    def generate(self, threat_event, base_explanation) -> "AIExplanation":
        """
        Entry point. Raises ValueError on None inputs. Returns cached if available.

        Args:
            threat_event: ThreatEvent instance (must not be None).
            base_explanation: Explanation instance (must not be None).

        Returns:
            AIExplanation with all required fields populated.

        Raises:
            ValueError: if either argument is None.
        """
        if threat_event is None or base_explanation is None:
            raise ValueError(
                "AIExplainService.generate() requires non-None threat_event and base_explanation"
            )

        event_id = getattr(threat_event, "event_id", None)

        # Cache lookup
        if event_id:
            cached = self._get_cached(event_id)
            if cached is not None:
                return cached

        result = self._call_provider(threat_event, base_explanation)

        if event_id:
            self._put_cached(event_id, result)

        return result

    # ------------------------------------------------------------------
    # Cache helpers
    # ------------------------------------------------------------------

    def _get_cached(self, event_id: str) -> Optional[AIExplanation]:
        """Return cached AIExplanation for event_id, promoting it to MRU, or None if absent."""
        with self._lock:
            if event_id in self._cache:
                self._cache.move_to_end(event_id)
                return self._cache[event_id]
        return None

    def _put_cached(self, event_id: str, result: AIExplanation) -> None:
        """LRU eviction: evicts oldest when cache exceeds _CACHE_SIZE."""
        with self._lock:
            if event_id in self._cache:
                self._cache.move_to_end(event_id)
            self._cache[event_id] = result
            if len(self._cache) > self._CACHE_SIZE:
                self._cache.popitem(last=False)  # evict oldest

    # ------------------------------------------------------------------
    # Provider dispatch
    # ------------------------------------------------------------------

    def _call_provider(self, threat_event, base_explanation) -> AIExplanation:
        """Dispatch to the configured provider (_call_gemini, _call_openai, or _call_stub)."""
        if self._provider == "gemini":
            return self._call_gemini(threat_event, base_explanation)
        if self._provider == "openai":
            return self._call_openai(threat_event, base_explanation)
        return self._call_stub(threat_event, base_explanation)

    def _call_stub(self, threat_event, base_explanation) -> AIExplanation:
        """Deterministic template-based response, no network call. < 100ms."""
        return self._stub_response(threat_event, base_explanation, is_fallback=False)

    def _call_gemini(self, threat_event, base_explanation) -> AIExplanation:
        """Calls google.generativeai. Falls back to stub on any exception."""
        try:
            import google.generativeai as genai  # type: ignore
            api_key = os.environ.get("GEMINI_API_KEY", "")
            if not api_key:
                raise RuntimeError("GEMINI_API_KEY not set")
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel("gemini-pro")
            prompt = self._build_prompt(threat_event, base_explanation)
            response = model.generate_content(prompt)
            return self._parse_llm_response(response.text, threat_event)
        except Exception as exc:
            logger.warning("Gemini provider failed (%s), using stub fallback", exc)
            return self._stub_response(threat_event, base_explanation, is_fallback=True)

    def _call_openai(self, threat_event, base_explanation) -> AIExplanation:
        """Calls openai.ChatCompletion. Falls back to stub on any exception."""
        try:
            import openai  # type: ignore
            api_key = os.environ.get("OPENAI_API_KEY", "")
            if not api_key:
                raise RuntimeError("OPENAI_API_KEY not set")
            openai.api_key = api_key
            prompt = self._build_prompt(threat_event, base_explanation)
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
            )
            raw = response.choices[0].message.content
            return self._parse_llm_response(raw, threat_event)
        except Exception as exc:
            logger.warning("OpenAI provider failed (%s), using stub fallback", exc)
            return self._stub_response(threat_event, base_explanation, is_fallback=True)

    def _build_prompt(self, threat_event, base_explanation) -> str:
        """Build the LLM prompt from event + explanation data."""
        return (
            f"You are a security analyst. Explain this threat in JSON format.\n"
            f"Attack: {getattr(threat_event, 'attack_type', 'Unknown')}\n"
            f"Severity: {getattr(threat_event, 'severity', 'Unknown')}\n"
            f"Source IP: {getattr(threat_event, 'source_ip', 'Unknown')}\n"
            f"Base explanation: {getattr(base_explanation, 'plain_english_text', '')}\n"
        )

    def _parse_llm_response(self, raw: str, threat_event) -> AIExplanation:
        """Parses LLM JSON or text response into AIExplanation. Falls back on parse error."""
        try:
            import json
            data = json.loads(raw)
            return AIExplanation(
                attack_name=data.get("attack_name", getattr(threat_event, "attack_type", "Unknown")),
                severity=data.get("severity", getattr(threat_event, "severity", "Medium")),
                confidence_pct=int(data.get("confidence_pct", getattr(threat_event, "confidence", 50))),
                description=data.get("description", ""),
                business_impact=data.get("business_impact", ""),
                attacker_methodology=data.get("attacker_methodology", ""),
                immediate_actions=list(data.get("immediate_actions", [])),
                long_term_recommendations=list(data.get("long_term_recommendations", [])),
                mitre_attack_mapping=list(data.get("mitre_attack_mapping", [])),
                cve_references=list(data.get("cve_references", [])),
                markdown_report=data.get("markdown_report", "") or self._build_markdown(
                    data.get("attack_name", getattr(threat_event, "attack_type", "Unknown")),
                    data.get("severity", getattr(threat_event, "severity", "Medium")),
                    data.get("description", ""),
                    data.get("business_impact", ""),
                    data.get("attacker_methodology", ""),
                    list(data.get("immediate_actions", [])),
                    list(data.get("long_term_recommendations", [])),
                    list(data.get("mitre_attack_mapping", [])),
                    list(data.get("cve_references", [])),
                ),
                is_fallback=False,
            )
        except Exception as exc:
            logger.warning("LLM response parse failed (%s), using stub", exc)
            return self._stub_response(threat_event, None, is_fallback=True)

    # ------------------------------------------------------------------
    # Stub / template builder
    # ------------------------------------------------------------------

    def _stub_response(self, threat_event, base_explanation, is_fallback: bool = False) -> AIExplanation:
        """Template builder always returns valid AIExplanation with all required sections."""
        attack = getattr(threat_event, "attack_type", "Unknown Attack")
        severity = getattr(threat_event, "severity", "Medium")
        confidence = getattr(threat_event, "confidence", 50)
        src_ip = getattr(threat_event, "source_ip", "unknown")

        immediate_actions = [
            f"Block source IP {src_ip} at the perimeter firewall.",
            "Review application and system logs for related activity.",
            "Notify the security operations team immediately.",
        ]
        long_term_recommendations = [
            "Implement network segmentation to limit lateral movement.",
            "Deploy an intrusion prevention system with up-to-date signatures.",
            "Conduct regular security audits and penetration testing.",
        ]
        mitre_attack_mapping = self._mitre_for(attack)
        cve_references = self._cves_for(attack)

        description = (
            f"A {severity.lower()}-severity {attack} was detected originating from {src_ip}. "
            f"Confidence level: {confidence}%."
        )
        business_impact = (
            f"This {attack} attack could compromise system availability, "
            f"data confidentiality, and business operations."
        )
        attacker_methodology = (
            f"The attacker is using {attack} techniques to exploit vulnerabilities. "
            f"Source IP {src_ip} is actively probing or attacking your systems."
        )

        markdown_report = self._build_markdown(
            attack, severity, description, business_impact, attacker_methodology,
            immediate_actions, long_term_recommendations, mitre_attack_mapping, cve_references,
        )

        return AIExplanation(
            attack_name=attack,
            severity=severity,
            confidence_pct=int(confidence),
            description=description,
            business_impact=business_impact,
            attacker_methodology=attacker_methodology,
            immediate_actions=immediate_actions,
            long_term_recommendations=long_term_recommendations,
            mitre_attack_mapping=mitre_attack_mapping,
            cve_references=cve_references,
            markdown_report=markdown_report,
            is_fallback=is_fallback,
        )

    def _build_markdown(
        self,
        attack: str,
        severity: str,
        description: str,
        business_impact: str,
        attacker_methodology: str,
        immediate_actions: list,
        long_term_recommendations: list,
        mitre_attack_mapping: list,
        cve_references: list,
    ) -> str:
        """Build the markdown_report string containing all 7 required section headers."""
        actions_md = "\n".join(f"- {a}" for a in immediate_actions) if immediate_actions else "- Review and respond."
        recs_md = "\n".join(f"- {r}" for r in long_term_recommendations) if long_term_recommendations else "- Implement security best practices."
        mitre_md = "\n".join(f"- {m}" for m in mitre_attack_mapping) if mitre_attack_mapping else "- N/A"
        cve_md = "\n".join(f"- {c}" for c in cve_references) if cve_references else "- No specific CVEs referenced."

        return (
            f"## Summary\n"
            f"{description}\n\n"
            f"## Business Impact\n"
            f"{business_impact}\n\n"
            f"## How the Attacker Works\n"
            f"{attacker_methodology}\n\n"
            f"## Immediate Actions\n"
            f"{actions_md}\n\n"
            f"## Long-term Recommendations\n"
            f"{recs_md}\n\n"
            f"## MITRE ATT&CK\n"
            f"{mitre_md}\n\n"
            f"## CVE References\n"
            f"{cve_md}\n"
        )

    @staticmethod
    def _mitre_for(attack_type: str) -> list:
        """Return relevant MITRE ATT&CK technique IDs for the given attack type."""
        mapping = {
            "SQL Injection":        ["T1190 - Exploit Public-Facing Application"],
            "Brute Force":          ["T1110 - Brute Force"],
            "Port Scan":            ["T1046 - Network Service Discovery"],
            "DDoS/SYN Flood":       ["T1498 - Network Denial of Service"],
            "SYN Flood":            ["T1498 - Network Denial of Service"],
            "XSS":                  ["T1059.007 - JavaScript"],
            "SSH Login":            ["T1021.004 - Remote Services: SSH"],
            "Suspicious DNS":       ["T1071.004 - Application Layer Protocol: DNS"],
            "Malware Download":     ["T1105 - Ingress Tool Transfer"],
            "Privilege Escalation": ["T1068 - Exploitation for Privilege Escalation"],
            "ARP Spoofing":         ["T1557.002 - ARP Cache Poisoning"],
        }
        return mapping.get(attack_type, ["T1001 - Data Obfuscation"])

    @staticmethod
    def _cves_for(attack_type: str) -> list:
        """Return well-known CVEs relevant to the attack type (illustrative)."""
        mapping = {
            "SQL Injection":    ["CVE-2012-1823"],
            "Malware Download": ["CVE-2021-44228"],
        }
        return mapping.get(attack_type, [])
