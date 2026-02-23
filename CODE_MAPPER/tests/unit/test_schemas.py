"""Test Pydantic schema validation."""

from schemas.models import Agent1bOutput, Agent1eOutput, ThreatModel


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
                    "divergence_note": "No input validation or parameterization",
                }
            },
            "insecure_practice_findings": [
                {
                    "id": "1B-001",
                    "file": "app.py",
                    "line_start": 9,
                    "line_end": 9,
                    "snippet": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
                    "category": "INSECURE_PRACTICE",
                    "cwe": "CWE-89",
                    "severity": "CRITICAL",
                    "description": "SQL injection via f-string concatenation",
                    "exploit_scenario": "Attacker sends id=1 OR 1=1 to extract all users",
                    "adversarial_check": "No parameterization used; direct concatenation confirmed",
                    "confidence": 0.95,
                    "confidence_reasoning": [
                        "Direct string concatenation with user input",
                        "SQL execute with unsanitized variable",
                    ],
                    "false_positive_risk": "LOW",
                    "false_positive_notes": "This is definitely a SQL injection vulnerability",
                }
            ],
        }
        output = Agent1bOutput(**data)
        assert "app.py::get_user" in output.semantics_map
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
                    "divergence_note": "",
                }
            },
            "insecure_practice_findings": [],
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
                            "sanitization_notes": "",
                        }
                    ],
                    "reaches_sinks": [
                        {
                            "sink_variable": "query",
                            "sink_line": 9,
                            "sink_fn": "execute",
                            "sink_type": "SQL_EXECUTION",
                            "path_is_reachable": True,
                            "reachability_notes": "Direct execution path",
                        }
                    ],
                }
            ],
            "taint_findings": [
                {
                    "id": "1E-TAINT-001",
                    "source": {"type": "HTTP_PARAM", "variable": "user_id", "line": 7},
                    "sink": {"type": "SQL_EXECUTION", "function": "execute", "line": 9},
                    "taint_path": ["HTTP_PARAM:user_id", "f-string query", "sql.execute"],
                    "sanitization": {
                        "exists": False,
                        "correct": False,
                        "sufficient": False,
                        "details": "No sanitization or parameterization applied",
                    },
                    "vulnerability": "SQL_INJECTION",
                    "cwe": "CWE-89",
                    "severity": "CRITICAL",
                    "domain_risk_context": "HIGH",
                    "exploit_scenario": "Attacker injects SQL via id parameter",
                    "verification_1_reachability": "Source reaches sink directly",
                    "verification_2_sanitization": "No defensive control observed",
                    "verification_3_adversarial": "Payload 1 OR 1=1 alters query semantics",
                    "confidence": 0.98,
                    "confidence_reasoning": [
                        "Untrusted source (HTTP parameter)",
                        "Dangerous sink (SQL execution)",
                    ],
                    "false_positive_risk": "LOW",
                    "false_positive_notes": "Direct concatenation into SQL query",
                    "remediation": "Use parameterized queries",
                    "snippet": "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
                }
            ],
            "clean_paths": [],
            "conflict_resolutions": [],
            "low_confidence_observations": [],
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
                    "sink_fn": "execute",
                    "reason_clean": "Properly parameterized SQL",
                }
            ],
            "conflict_resolutions": [],
            "low_confidence_observations": [],
        }
        output = Agent1eOutput(**data)
        assert len(output.taint_findings) == 0
        assert len(output.clean_paths) > 0


class TestThreatModel:
    """Test threat model schema."""

    def test_threat_model_creation(self):
        """Create a basic threat model."""
        data = {
            "methodology": "STRIDE",
            "domain": "test_app",
            "domain_risk_tier": "HIGH",
            "regulatory_context": [],
            "assets": [
                {
                    "asset_id": "A-1",
                    "name": "User records",
                    "classification": "PII",
                    "location": "postgres",
                    "value": "HIGH",
                    "value_reasoning": "Contains sensitive user data",
                }
            ],
            "trust_boundaries": [
                {
                    "boundary_id": "TB-1",
                    "name": "Internet to API",
                    "from_zone": "internet",
                    "to_zone": "backend",
                    "crossing_components": ["nginx", "api"],
                    "data_crossing": ["http requests"],
                }
            ],
            "attack_surface": [
                {
                    "surface_id": "AS-1",
                    "component": "api",
                    "entry_point": "GET /users/{id}",
                    "trust_boundary_crossed": "TB-1",
                    "accepts_untrusted_input": True,
                    "input_type": "http_param",
                    "exposed_assets": ["A-1"],
                }
            ],
            "stride_analysis": [
                {
                    "component": "api",
                    "threat_category": "Tampering",
                    "threat_id": "T-1",
                    "threat_description": "SQL injection may alter backend query behavior",
                    "affected_assets": ["A-1"],
                    "attack_vector": "Unsanitized query parameter",
                    "likelihood": "HIGH",
                    "likelihood_reasoning": "Public endpoint and direct query usage",
                    "impact": "HIGH",
                    "impact_reasoning": "Potential full table exposure",
                    "risk_score": "CRITICAL",
                    "existing_controls": [],
                    "control_adequacy": "NONE",
                    "related_terrain_sources": ["api.py:request.args.id"],
                    "related_terrain_sinks": ["db.py:execute"],
                }
            ],
            "prioritized_threat_scenarios": [
                {
                    "scenario_id": "TS-1",
                    "rank": 1,
                    "title": "Exploit SQL injection via user id",
                    "narrative": "Attacker injects SQL payload through id parameter",
                    "threat_ids": ["T-1"],
                    "entry_point": "GET /users/{id}",
                    "targeted_assets": ["A-1"],
                    "risk_score": "CRITICAL",
                    "taint_paths_to_investigate": ["api.py:id -> db.py:execute"],
                }
            ],
        }
        threat_model = ThreatModel(**data)
        assert threat_model.domain == "test_app"
        assert threat_model.stride_analysis[0].threat_category == "Tampering"
