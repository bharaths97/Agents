"""Test Agent1b (Code Semantics Analyst)."""
import pytest
from unittest.mock import patch
from agents.agent_1b import Agent1b


@pytest.mark.asyncio
async def test_agent_1b_finds_sql_injection(fixture_repo_py_simple_sqli, mock_openai_client):
    """Agent1b detects SQL injection in code."""
    agent = Agent1b(model="gpt-4o")

    agent_1b_response = {
        "semantics_map": {
            "app.py::get_user": {
                "intended": "Fetch user by ID",
                "actual": "Direct SQL concatenation",
                "diverges": True,
                "divergence_note": "No parameterization used"
            },
            "app.py::get_post": {
                "intended": "Fetch post by ID",
                "actual": "Parameterized SQL query",
                "diverges": False,
                "divergence_note": ""
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
                "description": "SQL injection via f-string",
                "exploit_scenario": "id=1 OR 1=1",
                "adversarial_check": "No parameterization",
                "confidence": 0.95,
                "confidence_reasoning": ["Direct concatenation", "User input"],
                "false_positive_risk": "LOW",
                "false_positive_notes": "Definitive SQL injection"
            }
        ]
    }

    with patch.object(agent, 'call_llm') as mock_call:
        mock_call.return_value = agent_1b_response
        result = await agent.run([fixture_repo_py_simple_sqli / "app.py"])

    assert len(result.insecure_practice_findings) > 0
    assert result.insecure_practice_findings[0].cwe == "CWE-89"


@pytest.mark.asyncio
async def test_agent_1b_identifies_safe_patterns(fixture_repo_py_simple_sqli):
    """Agent1b recognizes safe parameterized queries."""
    agent = Agent1b(model="gpt-4o")

    response = {
        "semantics_map": {
            "app.py::get_post": {
                "intended": "Fetch post safely",
                "actual": "Parameterized SQL",
                "diverges": False,
                "divergence_note": ""
            }
        },
        "insecure_practice_findings": []
    }

    with patch.object(agent, 'call_llm') as mock_call:
        mock_call.return_value = response
        result = await agent.run([fixture_repo_py_simple_sqli / "app.py"])

    assert len(result.insecure_practice_findings) == 0
