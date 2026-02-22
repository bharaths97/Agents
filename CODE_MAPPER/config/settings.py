from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    openai_api_key: str = ""
    openai_base_url: str | None = None
    openai_organization: str | None = None
    openai_project: str | None = None
    openai_model: str = "gpt-4o"
    openai_embedding_model: str = "text-embedding-3-small"
    log_level: str = "INFO"
    max_tokens_per_chunk: int = 8000
    concurrent_file_workers: int = 3
    min_confidence_reasons: int = 2
    auto_downgrade_high_severity: bool = True
    rag_docs_path: str = "rag/docs"
    semgrep_enabled: bool = True
    semgrep_binary: str = "semgrep"
    semgrep_app_token: str = ""
    semgrep_rules_root: str = "/semgrep-rules"
    semgrep_max_rules: int = 800
    semgrep_timeout_sec: int = 180
    semgrep_max_findings_per_file: int = 50
    semgrep_index_cache_file: str = "output/semgrep_rules_index.json"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
