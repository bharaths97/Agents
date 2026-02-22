"""Test configuration loading."""
import pytest
from config import settings


class TestSettings:
    """Test Pydantic settings."""

    def test_settings_loads(self, settings_override):
        """Settings loads with test env vars."""
        from config import settings as fresh_settings
        assert fresh_settings.openai_api_key == "test-key-12345"
        assert fresh_settings.openai_model == "gpt-4o"
        assert fresh_settings.log_level == "DEBUG"

    def test_settings_defaults(self, settings_override):
        """Settings have reasonable defaults."""
        from config import settings as fresh_settings
        assert fresh_settings.concurrent_file_workers > 0
        assert fresh_settings.max_tokens_per_chunk > 0
        assert fresh_settings.min_confidence_reasons >= 0
