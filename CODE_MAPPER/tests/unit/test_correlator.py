"""Unit tests for Phase 2 findings correlator."""

from pathlib import Path

from schemas.models import Agent1eOutput
from validation.correlator import FindingsCorrelator


def _finding(
    finding_id: str,
    source_line: int,
    sink_line: int,
    severity: str = "HIGH",
    confidence: float = 0.70,
):
    return {
        "id": finding_id,
        "source": {"variable": "user_id", "line": source_line, "type": "http_param"},
        "sink": {"variable": "query", "line": sink_line, "sink_fn": "execute", "type": "sql_exec"},
        "taint_path": [f"Line {source_line}: source", f"Line {sink_line}: sink"],
        "sanitization": {"exists": False, "correct": False, "sufficient": False, "details": "none"},
        "vulnerability": "SQL_INJECTION",
        "cwe": "CWE-89",
        "severity": severity,
        "domain_risk_context": "HIGH",
        "exploit_scenario": "unsanitized user input reaches SQL execute",
        "verification_1_reachability": "reachable",
        "verification_2_sanitization": "no sanitization",
        "verification_3_adversarial": "not refuted",
        "confidence": confidence,
        "confidence_reasoning": ["Direct source-to-sink path."],
        "false_positive_risk": "LOW",
        "false_positive_notes": "fixture",
        "remediation": "use parameterized query",
    }


def test_correlator_deduplicates_and_merges_semgrep_evidence(tmp_path):
    file_path = tmp_path / "api.py"
    file_path.write_text("# fixture\n")
    file_abs = str(Path(file_path).resolve())

    output_a = Agent1eOutput(file=file_abs, taint_findings=[_finding("1E-001", 10, 20, confidence=0.71)])
    output_b = Agent1eOutput(file=file_abs, taint_findings=[_finding("1E-002", 10, 20, confidence=0.66)])

    semgrep_by_file = {
        file_abs: [
            {
                "rule_id": "python.sql-injection.raw",
                "file": file_abs,
                "line": 21,
                "severity": "ERROR",
                "message": "Potential SQL injection",
                "cwe": ["CWE-89"],
            }
        ]
    }

    correlator = FindingsCorrelator()
    correlated = correlator.correlate(
        outputs=[output_a, output_b],
        semgrep_findings_by_file=semgrep_by_file,
        phase3_links=[],
    )

    assert len(correlated) == 1
    item = correlated[0]
    assert item["correlation_id"] == "CF-001"
    assert sorted(item["merged_finding_ids"]) == ["1E-001", "1E-002"]
    assert item["evidence_summary"]["semgrep_hits"] == 1
    assert item["confidence_adjusted"] > item["confidence_base"]
    assert item["source_agents"] == ["1E", "SEMGREP"]


def test_correlator_ranking_prefers_higher_severity_with_similar_confidence(tmp_path):
    high_file = tmp_path / "high.py"
    med_file = tmp_path / "med.py"
    high_file.write_text("# fixture\n")
    med_file.write_text("# fixture\n")

    high_output = Agent1eOutput(
        file=str(high_file.resolve()),
        taint_findings=[_finding("1E-H", 5, 15, severity="HIGH", confidence=0.68)],
    )
    med_output = Agent1eOutput(
        file=str(med_file.resolve()),
        taint_findings=[_finding("1E-M", 8, 22, severity="MEDIUM", confidence=0.69)],
    )

    correlator = FindingsCorrelator()
    correlated = correlator.correlate(outputs=[high_output, med_output])

    assert len(correlated) == 2
    assert correlated[0]["severity"] == "HIGH"
    assert correlated[0]["rank_score"] >= correlated[1]["rank_score"]
    assert correlated[0]["correlation_id"] == "CF-001"
    assert correlated[1]["correlation_id"] == "CF-002"
