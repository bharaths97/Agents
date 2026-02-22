"""Test Agent1a (Context & Domain Reader)."""
import pytest
import json
from unittest.mock import Mock, patch
from agents.agent_1a import Agent1a


@pytest.mark.asyncio
async def test_agent_1a_reads_readme(fixture_repo_py_simple_sqli, mock_openai_client):
    """Agent1a reads README and extracts domain context."""
    agent = Agent1a(model="gpt-4o")

    # Mock LLM response for this fixture
    agent_1a_response = {
        "domain": "web application",
        "domain_risk_tier": "HIGH",
        "domain_risk_reasoning": "Web-facing application handling user PII without apparent input validation",
        "regulatory_context": [],
        "user_types": [
            {
                "type": "anonymous",
                "trust_level": "UNTRUSTED",
                "description": "Unauthenticated web user"
            }
        ],
        "data_handled": [
            {
                "data_type": "user records",
                "sensitivity": "PII",
                "notes": "Stored in SQLite"
            }
        ],
        "component_intent_map": {
            "app.py": "Flask web API endpoint"
        },
        "intended_security_posture": "Basic input validation (not found)",
        "deployment_context": {
            "environment": "cloud",
            "publicly_exposed": True,
            "authentication_mechanism": "none",
            "notable_infrastructure": []
        },
        "test_derived_assumptions": [],
        "notable_developer_comments": [],
        "flags": ["No input validation comments", "SQL queries suggest injection awareness"]
    }

    with patch.object(agent, 'call_llm') as mock_call:
        mock_call.return_value = agent_1a_response
        result = await agent.run([fixture_repo_py_simple_sqli / "README.md"])

    assert result.domain == "web application"
    assert result.domain_risk_tier == "HIGH"
    assert result.publicly_exposed is True


@pytest.mark.asyncio
async def test_agent_1a_hipaa_context(fixture_repo_hipaa_context):
    """Agent1a detects HIPAA context from README."""
    agent = Agent1a(model="gpt-4o")

    hipaa_response = {
        "domain": "patient health record system",
        "domain_risk_tier": "CRITICAL",
        "domain_risk_reasoning": "Processes PHI (Protected Health Information) under HIPAA",
        "regulatory_context": ["HIPAA"],
        "user_types": [],
        "data_handled": [
            {
                "data_type": "PHI",
                "sensitivity": "CRITICAL",
                "notes": "Patient health records"
            }
        ],
        "component_intent_map": {},
        "intended_security_posture": "HIPAA-compliant encryption and access control",
        "deployment_context": {
            "environment": "cloud",
            "publicly_exposed": False,
            "authentication_mechanism": "OAuth2",
            "notable_infrastructure": ["PostgreSQL"]
        },
        "test_derived_assumptions": [],
        "notable_developer_comments": [],
        "flags": ["HIPAA mentions in README", "PHI handling evident"]
    }

    with patch.object(agent, 'call_llm') as mock_call:
        mock_call.return_value = hipaa_response
        result = await agent.run([fixture_repo_hipaa_context / "README.md"])

    assert "HIPAA" in result.regulatory_context
    assert result.domain_risk_tier == "CRITICAL"
