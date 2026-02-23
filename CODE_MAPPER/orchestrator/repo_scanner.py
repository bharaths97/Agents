from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
    ".idea",
    ".vscode",
}

CODE_EXTENSIONS = {
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".vue",
    ".svelte",
    ".go",
    ".java",
    ".scala",
    ".sc",
    ".groovy",
    ".gradle",
    ".kts",
    ".rb",
    ".php",
    ".pl",
    ".pm",
    ".lua",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".cs",
    ".fs",
    ".fsx",
    ".rs",
    ".swift",
    ".kt",
    ".dart",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".sql",
    ".ex",
    ".exs",
    ".erl",
    ".hrl",
    ".r",
    ".jl",
}

DOC_EXTENSIONS = {".md", ".rst", ".txt", ".adoc"}
CONFIG_EXTENSIONS = {".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".env", ".json"}

CODE_FILENAMES = {
    "jenkinsfile",
    "makefile",
    "rakefile",
    "gulpfile.js",
    "gruntfile.js",
    "dockerfile",
}

SHEBANG_CODE_TOKENS = {
    "python",
    "node",
    "bash",
    "sh",
    "zsh",
    "ruby",
    "php",
    "perl",
    "lua",
    "pwsh",
}

CONTEXT_FILE_NAMES = {
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "makefile",
    "readme",
    "readme.md",
    ".env.example",
    "openapi.yaml",
    "openapi.yml",
    "swagger.yaml",
    "swagger.yml",
}


@dataclass
class RepoScanResult:
    code_files: List[Path]
    context_files: List[Path]
    unknown_files: List[Path]
    detected_languages: Dict[str, int]
    detected_frameworks: List[str]
    detected_infra: List[str]
    manifests: List[Path] = field(default_factory=list)


class RepoScanner:
    def __init__(self, repo_path: Path):
        self.repo_path = repo_path

    def scan(self) -> RepoScanResult:
        code_files: List[Path] = []
        context_files: List[Path] = []
        unknown_files: List[Path] = []
        language_counts: Dict[str, int] = {}
        manifests: List[Path] = []

        for path in self._iter_files():
            name = path.name.lower()
            suffix = path.suffix.lower()

            if self._is_code_file(path):
                code_files.append(path)
                language_key = suffix or name
                language_counts[language_key] = language_counts.get(language_key, 0) + 1
                continue

            is_context = (
                suffix in DOC_EXTENSIONS
                or suffix in CONFIG_EXTENSIONS
                or name in CONTEXT_FILE_NAMES
                or "test" in name
                or path.parts and any(part.lower() in {"tests", "docs", ".github"} for part in path.parts)
            )
            if is_context:
                context_files.append(path)
            elif self._is_text_file(path):
                unknown_files.append(path)

            if name in {"requirements.txt", "pyproject.toml", "package.json", "pom.xml", "go.mod", "cargo.toml"}:
                manifests.append(path)

        frameworks, infra = self._detect_stack(manifests, context_files)
        return RepoScanResult(
            code_files=sorted(code_files),
            context_files=sorted(context_files),
            unknown_files=sorted(unknown_files),
            detected_languages=dict(sorted(language_counts.items(), key=lambda kv: kv[0])),
            detected_frameworks=sorted(frameworks),
            detected_infra=sorted(infra),
            manifests=sorted(manifests),
        )

    def _iter_files(self):
        for path in self.repo_path.rglob("*"):
            if not path.is_file():
                continue
            if self._should_skip(path):
                continue
            try:
                if path.stat().st_size > 2_000_000:
                    continue
            except OSError:
                continue
            yield path

    def _should_skip(self, path: Path) -> bool:
        rel_parts = path.relative_to(self.repo_path).parts
        return any(part in SKIP_DIRS for part in rel_parts)

    def _is_code_file(self, path: Path) -> bool:
        suffix = path.suffix.lower()
        name = path.name.lower()

        if suffix in CODE_EXTENSIONS:
            return True
        if name in CODE_FILENAMES:
            return True
        return self._has_code_shebang(path)

    def _has_code_shebang(self, path: Path) -> bool:
        try:
            with path.open("rb") as f:
                line = f.readline(256)
            if not line.startswith(b"#!"):
                return False
            try:
                shebang = line.decode("utf-8", errors="ignore").lower()
            except Exception:
                return False
            return any(token in shebang for token in SHEBANG_CODE_TOKENS)
        except Exception:
            return False

    def _is_text_file(self, path: Path) -> bool:
        try:
            with path.open("rb") as f:
                chunk = f.read(2048)
            if b"\x00" in chunk:
                return False
            if not chunk:
                return True
            chunk.decode("utf-8", errors="ignore")
            return True
        except Exception:
            return False

    def _detect_stack(
        self,
        manifests: List[Path],
        context_files: List[Path],
    ) -> tuple[Set[str], Set[str]]:
        frameworks: Set[str] = set()
        infra: Set[str] = set()

        for manifest in manifests:
            text = manifest.read_text(encoding="utf-8", errors="replace").lower()
            if "django" in text:
                frameworks.add("django")
            if "flask" in text:
                frameworks.add("flask")
            if "fastapi" in text:
                frameworks.add("fastapi")
            if "express" in text:
                frameworks.add("express")
            if "spring-boot" in text or "springframework" in text:
                frameworks.add("spring")
            if "gin-gonic" in text or "\ngin " in text:
                frameworks.add("gin")

        for file_path in context_files:
            name = file_path.name.lower()
            if "docker" in name:
                infra.add("docker")
            if "k8s" in name or "kubernetes" in name:
                infra.add("kubernetes")
            if "nginx" in name:
                infra.add("nginx")
            if name in {"terraform.tf", "main.tf"} or file_path.suffix == ".tf":
                infra.add("terraform")

        return frameworks, infra
