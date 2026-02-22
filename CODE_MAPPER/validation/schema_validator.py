from __future__ import annotations

import logging
from typing import List

from config import settings
from schemas.models import Agent1aOutput, Agent1bOutput, Agent1cOutput, Agent1eOutput, TaintFinding

logger = logging.getLogger(__name__)

SEVERITY_DOWNGRADE = {
    "CRITICAL": "HIGH",
    "HIGH": "MEDIUM",
    "MEDIUM": "LOW",
    "LOW": "LOW",
}


class SchemaValidator:
    """Validation + anti-hallucination enforcement for parsed model outputs."""

    def validate_1a_output(self, output: Agent1aOutput) -> Agent1aOutput:
        return Agent1aOutput(**output.model_dump())

    def validate_1b_output(self, output: Agent1bOutput) -> Agent1bOutput:
        return Agent1bOutput(**output.model_dump())

    def validate_1c_output(self, output: Agent1cOutput) -> Agent1cOutput:
        return Agent1cOutput(**output.model_dump())

    def validate_1e_output(self, output: Agent1eOutput) -> Agent1eOutput:
        validated_findings: List[TaintFinding] = []
        for finding in output.taint_findings:
            validated_findings.append(self._enforce_finding_rules(finding))

        return Agent1eOutput(
            file=output.file,
            pass1_flow_map=output.pass1_flow_map,
            taint_findings=validated_findings,
            conflict_resolutions=output.conflict_resolutions,
            clean_paths=output.clean_paths,
            low_confidence_observations=output.low_confidence_observations,
        )

    def _enforce_finding_rules(self, finding: TaintFinding) -> TaintFinding:
        confidence = finding.confidence
        severity = finding.severity
        reasons = finding.confidence_reasoning
        false_positive_notes = finding.false_positive_notes

        if confidence >= 0.7 and len(reasons) < settings.min_confidence_reasons:
            confidence = min(confidence, 0.69)
            false_positive_notes = self._append_note(
                false_positive_notes,
                "Auto-adjusted confidence due to insufficient confidence_reasoning entries.",
            )

        if settings.auto_downgrade_high_severity and severity in {"HIGH", "CRITICAL"}:
            if len(reasons) < settings.min_confidence_reasons:
                severity = SEVERITY_DOWNGRADE[severity]
                false_positive_notes = self._append_note(
                    false_positive_notes,
                    "Severity downgraded because high-severity finding had insufficient support.",
                )

        evidence_missing = (
            not finding.snippet
            or int(finding.source.get("line", 0) or 0) <= 0
            or int(finding.sink.get("line", 0) or 0) <= 0
        )
        if evidence_missing:
            confidence = min(confidence, 0.49)
            false_positive_notes = self._append_note(
                false_positive_notes,
                "Evidence incomplete (snippet/source line/sink line missing).",
            )

        if severity in {"HIGH", "CRITICAL"} and not finding.cwe.startswith("CWE-"):
            severity = SEVERITY_DOWNGRADE[severity]
            false_positive_notes = self._append_note(
                false_positive_notes,
                "Severity downgraded because CWE mapping is missing or malformed.",
            )

        try:
            return finding.model_copy(
                update={
                    "confidence": round(max(min(confidence, 1.0), 0.0), 4),
                    "severity": severity,
                    "false_positive_notes": false_positive_notes,
                }
            )
        except Exception as exc:
            logger.warning("Could not apply validation updates to finding %s: %s", finding.id, exc)
            return finding

    @staticmethod
    def _append_note(original: str, extra: str) -> str:
        if not original:
            return extra
        if extra in original:
            return original
        return f"{original} {extra}"
