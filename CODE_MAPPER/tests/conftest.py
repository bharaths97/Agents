"""Global test fixtures and configuration."""
import pytest
import json
from pathlib import Path
from unittest.mock import Mock, AsyncMock, MagicMock
from typing import Dict, Any

# Set test environment variables before importing settings
import os
os.environ.setdefault("OPENAI_API_KEY", "test-key-12345")
os.environ.setdefault("OPENAI_MODEL", "gpt-4o")
os.environ.setdefault("LOG_LEVEL", "DEBUG")
os.environ.setdefault("SEMGREP_ENABLED", "false")


@pytest.fixture
def mock_openai_client():
    """Mock AsyncOpenAI client returning pre-canned responses."""
    client = Mock()

    # Default Agent 1a response
    agent_1a_response = {
        "domain": "test web application",
        "domain_risk_tier": "HIGH",
        "domain_risk_reasoning": "Web-facing application handling user data without apparent HIPAA/PCI compliance",
        "regulatory_context": [],
        "user_types": [
            {
                "type": "anonymous",
                "trust_level": "UNTRUSTED",
                "description": "Unauthenticated internet user"
            }
        ],
        "data_handled": [
            {
                "data_type": "user records",
                "sensitivity": "PII",
                "notes": "Stored in SQLite database"
            }
        ],
        "component_intent_map": {
            "app.py": "Flask web API serving user endpoints"
        },
        "intended_security_posture": "Basic input validation (not evident in code)",
        "deployment_context": {
            "environment": "cloud",
            "publicly_exposed": True,
            "authentication_mechanism": "none",
            "notable_infrastructure": []
        },
        "test_derived_assumptions": [],
        "notable_developer_comments": [],
        "flags": ["No input validation comments", "Direct SQL queries suggest injection risk"]
    }

    client.chat.completions.create = AsyncMock(
        return_value=Mock(
            choices=[Mock(message=Mock(content=json.dumps(agent_1a_response)))]
        )
    )
    return client


@pytest.fixture
def settings_override(monkeypatch):
    """Override environment settings for testing."""
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-12345")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-4o")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("SEMGREP_ENABLED", "false")
    monkeypatch.setenv("MAX_TOKENS_PER_CHUNK", "20000")
    monkeypatch.setenv("CONCURRENT_FILE_WORKERS", "2")


@pytest.fixture
def fixture_repo_py_simple_sqli(tmp_path):
    """Create minimal Python repo with SQL injection vulnerability."""
    repo = tmp_path / "py_simple_sqli"
    repo.mkdir()

    (repo / "app.py").write_text("""from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL injection!
    result = conn.execute(query)
    return str(result.fetchone())

@app.route('/post/<post_id>')
def get_post(post_id):
    # Safe version with parameterized query
    conn = sqlite3.connect('db.sqlite')
    query = "SELECT * FROM posts WHERE id = ?"
    result = conn.execute(query, (post_id,))
    return str(result.fetchone())
""")

    (repo / "README.md").write_text("""# Simple Web App

A basic Flask web application for testing.

## Domain
Web API serving user data.
""")

    (repo / "requirements.txt").write_text("""flask==2.3.0
""")

    return repo


@pytest.fixture
def fixture_repo_js_xss(tmp_path):
    """Create minimal JavaScript repo with XSS vulnerability."""
    repo = tmp_path / "js_xss"
    repo.mkdir()

    (repo / "app.js").write_text("""const express = require('express');
const app = express();

app.get('/comment/:id', (req, res) => {
    const commentId = req.params.id;
    const comment = getCommentFromDB(commentId);

    // Unsafe: directly injecting user content into HTML
    res.send(`<div>${comment.text}</div>`);  // XSS!
});

app.get('/safe-comment/:id', (req, res) => {
    const commentId = req.params.id;
    const comment = getCommentFromDB(commentId);

    // Safe: escaping HTML
    const escaped = escapeHtml(comment.text);
    res.send(`<div>${escaped}</div>`);
});

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}
""")

    (repo / "package.json").write_text("""{
  "name": "js-xss-test",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0"
  }
}
""")

    return repo


@pytest.fixture
def fixture_repo_multifile(tmp_path):
    """Create multi-file repository for cross-file taint tracing."""
    repo = tmp_path / "mixed_multifile"
    repo.mkdir()

    (repo / "api.py").write_text("""from flask import Flask, request
from db import execute_query

app = Flask(__name__)

@app.route('/search')
def search():
    search_term = request.args.get('q')
    # Passes unsanitized input to db module
    results = execute_query(search_term)
    return {'results': results}
""")

    (repo / "db.py").write_text("""import sqlite3

def execute_query(search_term):
    # Receives unsanitized input from api.py
    conn = sqlite3.connect('app.db')
    query = f"SELECT * FROM items WHERE name LIKE '%{search_term}%'"  # SQL injection!
    return conn.execute(query).fetchall()
""")

    (repo / "README.md").write_text("# Multi-file Web App")

    return repo


@pytest.fixture
def fixture_repo_hipaa_context(tmp_path):
    """Create repository with HIPAA context (healthcare domain)."""
    repo = tmp_path / "hipaa_context"
    repo.mkdir()

    (repo / "README.md").write_text("""# Patient Management System

This is a HIPAA-compliant patient health record system.

## Compliance
- HIPAA certification in progress
- Processes PHI (Protected Health Information)
- Encryption at rest and in transit required

## Architecture
- FastAPI backend
- PostgreSQL database
- OAuth2 authentication
""")

    (repo / "patient_api.py").write_text("""from fastapi import FastAPI, Depends
from database import get_db

app = FastAPI()

@app.get("/patient/{patient_id}")
async def get_patient_record(patient_id: int, db=Depends(get_db)):
    # Should enforce that user can only access their own record
    # Currently vulnerable to BOLA (Broken Object Level Authorization)
    query = f"SELECT * FROM patients WHERE id = {patient_id}"
    return db.execute(query).fetchone()
""")

    (repo / "database.py").write_text("""import psycopg2

def get_db():
    return psycopg2.connect("dbname=patients user=app password=hardcoded")
""")

    return repo


@pytest.fixture
def expected_output_py_sqli():
    """Expected analysis output for py_simple_sqli fixture."""
    return {
        "domain": "web application",
        "domain_risk_tier": "HIGH",
        "vulnerabilities": [
            {
                "type": "SQL_INJECTION",
                "file": "app.py",
                "line": 9,
                "severity": "CRITICAL",
                "cwe": "CWE-89"
            }
        ],
        "safe_patterns": [
            {
                "type": "PARAMETERIZED_QUERY",
                "file": "app.py",
                "line": 18
            }
        ]
    }


@pytest.fixture
def expected_output_js_xss():
    """Expected analysis output for js_xss fixture."""
    return {
        "domain": "web application",
        "vulnerabilities": [
            {
                "type": "CROSS_SITE_SCRIPTING",
                "file": "app.js",
                "line": 8,
                "severity": "HIGH",
                "cwe": "CWE-79"
            }
        ]
    }


@pytest.fixture
def mock_semgrep_findings():
    """Mock Semgrep findings for testing."""
    return {
        "app.py": [
            {
                "check_id": "python.lang.best-practice.use-urllib-parse.use-urllib-parse",
                "path": "app.py",
                "line": 9,
                "column": 12,
                "message": "Direct SQL query concatenation detected",
                "severity": "ERROR"
            }
        ]
    }


@pytest.fixture
def mock_rag_store():
    """Mock RAG store for testing."""
    store = AsyncMock()
    store.query = AsyncMock(
        return_value=[
            {
                "source": "cwe_quick_map.md",
                "section": "CWE-89",
                "text": "SQL Injection — Improper control of generated SQL. Use parameterized queries."
            }
        ]
    )
    return store
