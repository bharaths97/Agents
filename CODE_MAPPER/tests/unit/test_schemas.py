"""Test Pydantic schema validation."""
import pytest
from schemas.models import (
    Agent1bOutput,
    Agent1eOutput,
    TaintFinding,
    ThreatModel,
    InsecurePracticeFinding,
)


class TestAgent1bOutput:
    """Test Agent1b schema validation."""

    def test_agent1b_output_validates_complete(self):
        """Pydantic schema validation for complete Agent 1b output."""
        data = {
            "semantics_map": {
                "app.py::get_user": {
                    "intended": "Fetch user by ID",
                    "actual": "Direct SQL query with string concatenation",
                    "diverges": True,
                    "divergence_note": "No input validation or parameterization"
                }
            },
            "insecure_practice_findings": [
                {
                    "id": "1B-001",
                    "file": "app.py",
                    "line_start": 9,
                    "line_end": 9,
                    "snippet": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
                    "category": "INJECTION_PATTERN",
                    "cwe": "CWE-89",
                    "severity": "CRITICAL",
                    "description": "SQL injection via f-string concatenation",
                    "exploit_scenario": "Attacker sends id=1 OR 1=1 to extract all users",
                    "adversarial_check": "No parameterization used; direct concatenation confirmed",
                    "confidence": 0.95,
                    "confidence_reasoning": [
                        "Direct string concatenation with user input",
                        "SQL execute with unsanitized variable"
                    ],
                    "false_positive_risk": "LOW",
                    "false_positive_notes": "This is definitely a SQL injection vulnerability"
                }
            ]
        }
        output = Agent1bOutput(**data)
        assert output.file == "app.py"
        assert len(output.insecure_practice_findings) == 1
        assert output.insecure_practice_findings[0].cwe == "CWE-89"

    def test_agent1b_output_empty_findings(self):
        """Agent1b with clean code (no findings)."""
        data = {
            "semantics_map": {
                "app.py::get_user": {
                    "intended": "Fetch user safely",
                    "actual": "Parameterized SQL query",
                    "diverges": False,
                    "divergence_note": ""
                }
            },
            "insecure_practice_findings": []
        }
        output = Agent1bOutput(**data)
        assert len(output.insecure_practice_findings) == 0


class TestAgent1eOutput:
    """Test Agent1e schema validation."""

    def test_agent1e_output_with_taint_findings(self):
        """Agent1e output with taint findings."""
        data = {
            "file": "app.py",
            "pass1_flow_map": [
                {
                    "pair_id": "SSP-001",
                    "source_variable": "user_id",
                    "source_line": 7,
                    "source_type": "HTTP_PARAM",
                    "data_classification": "PII",
                    "transformation_chain": [
                        {
                            "step": 1,
                            "line": 9,
                            "operation": "f-string concatenation",
                            "sanitization_applied": False,
                            "sanitization_notes": ""
                        }
                    ],
                    "reaches_sinks": [
                        {
                            "sink_variable": "query",
                            "sink_line": 9,
                            "sink_fn": "execute",
                            "sink_type": "SQL_EXECUTION",
                            "path_is_reachable": True,
                            "reachability_notes": "Direct execution path"
                        }
                    ],
                    "linked_threat_scenario": "TS-001"
                }
            ],
            "taint_findings": [
                {
                    "id": "1E-TAINT-001",
                    "file": "app.py",
                    "line_start": 7,
                    "line_end": 9,
                    "snippet": "user_id = request.args.get('id')\nquery = f\"SELECT * FROM users WHERE id = {user_id}\"",
                    "vulnerability": "SQL_INJECTION",
                    "cwe": "CWE-89",
                    "severity": "CRITICAL",
                    "confidence": 0.98,
                    "description": "SQL injection from unsanitized HTTP parameter",
                    "source": "HTTP_PARAM (user_id)",
                    "sink": "SQL_EXECUTE",
                    "taint_path": "HTTP_PARAM → f-string → SQL execute()",
                    "exploit_scenario": "Attacker: GET /user?id=1 OR 1=1 → extracts all user records",
                    "adversarial_check": "Parameterization would fix. User input has full control over query structure.",
                    "confidence_reasoning": [
                        "Untrusted source (HTTP parameter)",
                        "No sanitization applied",
                        "Dangerous sink (SQL execution)"
                    ],
                    "false_positive_risk": "VERY_LOW",
                    "false_positive_notes": "Definitive injection vulnerability"
                }
            ],
            "clean_paths": [],
            "conflict_resolutions": [],
            "low_confidence_observations": []
        }
        output = Agent1eOutput(**data)
        assert output.file == "app.py"
        assert len(output.taint_findings) == 1
        assert output.taint_findings[0].severity == "CRITICAL"

    def test_agent1e_output_no_vulnerabilities(self):
        """Agent1e on safe code."""
        data = {
            "file": "safe.py",
            "pass1_flow_map": [],
            "taint_findings": [],
            "clean_paths": [
                {
                    "source_variable": "user_id",
                    "source_line": 7,
                    "sink_variable": "query",
                    "sanitization_method": "parameterized_query",
                    "notes": "Properly parameterized SQL"
                }
            ],
            "conflict_resolutions": [],
            "low_confidence_observations": []
        }
        output = Agent1eOutput(**data)
        assert len(output.taint_findings) == 0
        assert len(output.clean_paths) > 0


class TestThreatModel:
    """Test threat model schema."""

    def test_threat_model_creation(self):
        """Create a basic threat model."""
        data = {
            "system_name": "test_app",
            "system_description": "Test application",
            "stride_categories": {
                "spoofing": ["No authentication mechanism detected"],
                "tampering": ["Inputs not validated"],
                "repudiation": ["Logging not configured"],
                "information_disclosure": ["Sensitive data in SQL queries"],
                "denial_of_service": ["No rate limiting"],
                "elevation_of_privilege": ["SQL injection allows data access"]
            },
            "prioritized_threat_scenarios": [],
            "domain_context": "web application",
            "domain_risk_tier": "HIGH"
        }
        threat_model = ThreatModel(**data)
        assert threat_model.system_name == "test_app"
        assert "spoofing" in threat_model.stride_categories
