from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    openai_api_key: str = ""
    openai_base_url: str | None = None
    openai_organization: str | None = None
    openai_project: str | None = None
    openai_model: str = "gpt-5-nano"
    openai_embedding_model: str = "text-embedding-3-small"
    log_level: str = "INFO"
    debug_dump: bool = False
    output_dir: str = "output"
    max_tokens_per_chunk: int = 8000
    concurrent_file_workers: int = 3
    min_confidence_reasons: int = 2
    auto_downgrade_high_severity: bool = True
    rag_docs_path: str = "rag/docs"
    repo_url: str = ""
    repo_branch: str = ""
    repo_commit: str = ""
    refresh_clone: bool = False
    semgrep_enabled: bool = True
    semgrep_binary: str = "semgrep"
    semgrep_app_token: str = ""
    semgrep_rules_root: str = "/semgrep-rules"
    semgrep_max_rules: int = 800
    semgrep_timeout_sec: int = 180
    semgrep_max_findings_per_file: int = 50
    semgrep_index_cache_file: str = "output/semgrep_rules_index.json"
    repo_clone_cache_dir: str = ".repo_cache"
    repo_clone_timeout_sec: int = 180
    repo_clone_max_attempts: int = 2
    repo_clone_depth: int = 1
    phase3_cross_file_enabled: bool = False
    phase3_call_graph_max_hops: int = 5
    phase3_call_graph_max_chains_per_file: int = 20

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
