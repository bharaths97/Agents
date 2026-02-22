"""Test repository scanner."""
import pytest
from orchestrator.repo_scanner import RepoScanner


class TestRepoScanner:
    """Test RepoScanner language and framework detection."""

    def test_detects_python(self, fixture_repo_py_simple_sqli):
        """RepoScanner identifies Python files."""
        scanner = RepoScanner(fixture_repo_py_simple_sqli)
        result = scanner.scan()
        assert ".py" in result.detected_languages
        assert any("app.py" in str(f) for f in result.code_files)

    def test_detects_javascript(self, fixture_repo_js_xss):
        """RepoScanner identifies JavaScript files."""
        scanner = RepoScanner(fixture_repo_js_xss)
        result = scanner.scan()
        assert ".js" in result.detected_languages
        assert any("app.js" in str(f) for f in result.code_files)

    def test_detects_flask_framework(self, fixture_repo_py_simple_sqli):
        """RepoScanner detects Flask from requirements.txt."""
        scanner = RepoScanner(fixture_repo_py_simple_sqli)
        result = scanner.scan()
        assert "flask" in [f.lower() for f in result.detected_frameworks]

    def test_detects_express_framework(self, fixture_repo_js_xss):
        """RepoScanner detects Express from package.json."""
        scanner = RepoScanner(fixture_repo_js_xss)
        result = scanner.scan()
        assert "express" in [f.lower() for f in result.detected_frameworks]

    def test_excludes_docs_and_config(self, fixture_repo_py_simple_sqli):
        """RepoScanner excludes README, config, test files."""
        scanner = RepoScanner(fixture_repo_py_simple_sqli)
        result = scanner.scan()
        # Only application code, not docs/config
        code_files = [str(f) for f in result.code_files]
        assert any("app.py" in f for f in code_files)
        assert not any("README" in f for f in code_files)
