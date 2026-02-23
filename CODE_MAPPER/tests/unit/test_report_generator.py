"""Unit tests for Phase 6 report generation."""

from pathlib import Path

from reports import ReportGenerator


def _payload(tmp_path):
    file_path = str((tmp_path / "app.py").resolve())
    return {
        "generated_at_utc": "2026-02-23T00:00:00+00:00",
        "repo_path": str(tmp_path),
        "model": "gpt-4o",
        "summary": {
            "correlated_findings": 2,
            "taint_findings": 3,
            "threat_scenarios": 1,
        },
        "results": {
            "correlated_findings": [
                {
                    "correlation_id": "CF-001",
                    "severity": "CRITICAL",
                    "cwe": "CWE-89",
                    "vulnerability": "SQL_INJECTION",
                    "files": [file_path],
                    "source_agents": ["1E", "SEMGREP"],
                    "confidence_base": 0.82,
                    "confidence_adjusted": 0.91,
                    "rank_score": 128.2,
                    "representative_finding": {
                        "source": {"line": 10, "type": "http_param"},
                        "sink": {"line": 22, "sink_fn": "execute", "type": "sql_exec"},
                        "taint_path": [
                            "Line 10: source",
                            "Line 22: sink",
                        ],
                        "exploit_scenario": "Attacker injects SQL payload in id parameter.",
                        "remediation": "Use parameterized query arguments.",
                        "snippet": "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
                        "crosses_file_boundary": True,
                        "boundary_hops": [
                            {
                                "from_file": file_path,
                                "from_function": "endpoint",
                                "to_file": file_path,
                                "to_function": "execute_query",
                                "call_line": 18,
                            }
                        ],
                    },
                },
                {
                    "correlation_id": "CF-002",
                    "severity": "MEDIUM",
                    "cwe": "CWE-200",
                    "vulnerability": "INFO_DISCLOSURE",
                    "files": [file_path],
                    "source_agents": ["1E"],
                    "confidence_base": 0.55,
                    "confidence_adjusted": 0.57,
                    "rank_score": 73.1,
                    "representative_finding": {
                        "source": {"line": 31, "type": "other"},
                        "sink": {"line": 33, "sink_fn": "logger.error", "type": "other"},
                        "taint_path": ["Line 31: exception", "Line 33: log sink"],
                        "exploit_scenario": "Sensitive exception data may be logged.",
                        "remediation": "Redact exception payload before logging.",
                        "snippet": "logger.error(str(exc))",
                    },
                },
            ],
            "threat_model": {
                "methodology": "STRIDE",
                "assets": [{"asset_id": "A-001"}],
                "trust_boundaries": [{"boundary_id": "TB-001"}],
                "attack_surface": [{"surface_id": "AS-001"}],
                "stride_analysis": [{"threat_id": "T-001"}],
                "prioritized_threat_scenarios": [
                    {
                        "scenario_id": "TS-001",
                        "rank": 1,
                        "risk_score": "CRITICAL",
                        "title": "SQLi chain",
                        "narrative": "Unsanitized id reaches SQL execution.",
                    }
                ],
            },
            "ctf_artifacts": {
                "summary": "1 potential CTF flag artifact(s) detected.",
                "hits": [
                    {
                        "match": "FLAG{demo}",
                        "file": file_path,
                        "line_start": 2,
                        "line_end": 2,
                    }
                ],
            },
            "agent_1a": {
                "domain": "test web app",
                "domain_risk_tier": "HIGH",
            },
        },
    }


def test_report_generator_writes_markdown_html_and_tickets(tmp_path):
    payload = _payload(tmp_path)
    output_dir = tmp_path / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)

    generator = ReportGenerator()
    paths = generator.generate_all(payload, output_dir=output_dir, base_stem="report_test")

    assert paths["markdown"].exists()
    assert paths["html"].exists()
    assert paths["tickets"].exists()

    markdown_text = paths["markdown"].read_text(encoding="utf-8")
    html_text = paths["html"].read_text(encoding="utf-8")
    tickets_text = paths["tickets"].read_text(encoding="utf-8")

    assert "Correlated Findings" in markdown_text
    assert "CF-001" in markdown_text
    assert "Cross-File Boundary Hops" in markdown_text
    assert "<!DOCTYPE html>" in html_text
    assert "CODE_MAPPER Security Report" in html_text
    assert "TICKET-CF-001" in tickets_text
    assert "CF-002" not in tickets_text


def test_report_generator_ticket_threshold_is_critical_high_only(tmp_path):
    payload = _payload(tmp_path)
    tickets = ReportGenerator().build_tickets(payload)

    assert len(tickets) == 1
    assert tickets[0]["source_correlation_id"] == "CF-001"
    assert tickets[0]["priority"] == "CRITICAL"
