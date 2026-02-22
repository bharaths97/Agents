from __future__ import annotations

import json
import logging
from typing import Any, Dict

from agents.base import BaseAgent
from schemas.models import TaintFinding

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """
You are an adversarial security reviewer. Challenge the claimed vulnerability.
Try to prove it is a false positive. Return strict JSON only:
{
  "keep_finding": true,
  "confidence_delta": -0.2,
  "false_positive_risk": "LOW | MEDIUM | HIGH",
  "counter_arguments": ["..."],
  "final_judgement": "..."
}
Rules:
- confidence_delta must be between -0.5 and 0.0.
- If decisive counter-evidence exists, set keep_finding=false.
- Keep output concise and factual.
"""

SEVERITY_DOWNGRADE = {
    "CRITICAL": "HIGH",
    "HIGH": "MEDIUM",
    "MEDIUM": "LOW",
    "LOW": "LOW",
}


class AdversarialVerifier(BaseAgent):
    name = "AdversarialVerifier"

    async def verify_taint_finding(self, finding: TaintFinding) -> TaintFinding:
        try:
            raw = await self.call_llm(
                system_prompt=SYSTEM_PROMPT,
                user_prompt=self._build_user_prompt(finding),
                temperature=0.0,
            )
            return self._apply_verdict(finding, raw)
        except Exception as exc:
            logger.warning("[AdversarialVerifier] Verification failed for %s: %s", finding.id, exc)
            return finding

    @staticmethod
    def _build_user_prompt(finding: TaintFinding) -> str:
        return (
            "Claimed finding to challenge:\n\n"
            + json.dumps(finding.model_dump(), indent=2)
            + "\n\nIdentify every reason this might not be a real vulnerability."
        )

    def _apply_verdict(self, finding: TaintFinding, verdict: Dict[str, Any]) -> TaintFinding:
        keep = bool(verdict.get("keep_finding", True))
        try:
            delta = float(verdict.get("confidence_delta", 0.0))
        except Exception:
            delta = 0.0
        delta = min(0.0, max(-0.5, delta))

        confidence = max(0.0, min(1.0, finding.confidence + delta))
        severity = finding.severity if keep else SEVERITY_DOWNGRADE[finding.severity]
        fp_risk = str(verdict.get("false_positive_risk", finding.false_positive_risk)).upper()
        if fp_risk not in {"LOW", "MEDIUM", "HIGH"}:
            fp_risk = finding.false_positive_risk

        counter = verdict.get("counter_arguments", [])
        if isinstance(counter, list):
            counter_text = "; ".join(str(c) for c in counter if c)
        else:
            counter_text = str(counter)
        judgement = str(verdict.get("final_judgement", "")).strip()
        verification_note = " ".join(p for p in [judgement, counter_text] if p).strip()

        if not verification_note:
            verification_note = finding.verification_3_adversarial

        return finding.model_copy(
            update={
                "confidence": round(confidence, 4),
                "severity": severity,
                "false_positive_risk": fp_risk,
                "verification_3_adversarial": verification_note,
            }
        )
