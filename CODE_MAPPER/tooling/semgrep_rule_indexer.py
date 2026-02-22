from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import yaml

logger = logging.getLogger(__name__)

RULE_FILE_SUFFIXES = {".yaml", ".yml"}
IGNORED_PATH_PARTS = {".git", ".github", "stats", "scripts"}
IGNORED_FILENAME_SUBSTRINGS = {".test.", ".fixed."}


@dataclass
class RuleRecord:
    rule_id: str
    rule_path: str
    top_level: str
    language_family: str
    languages: List[str]
    severity: str
    mode: str
    category: str
    subcategory: List[str]
    technology: List[str]
    cwe: List[str]
    owasp: List[str]
    references: List[str]
    source_rule_url: str
    likelihood: str
    impact: str
    confidence: str


@dataclass
class RuleIndex:
    generated_at_utc: str
    rules_root: str
    repo_commit_sha: str
    total_files_scanned: int
    total_rules_indexed: int
    records: List[RuleRecord]

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["records"] = [asdict(record) for record in self.records]
        return payload


class SemgrepRuleIndexer:
    def __init__(self, rules_root: Path):
        self.rules_root = rules_root

    def build(self) -> RuleIndex:
        if not self.rules_root.exists():
            raise FileNotFoundError(f"Semgrep rules root does not exist: {self.rules_root}")

        rule_files = [path for path in self.rules_root.rglob("*") if self._is_rule_file(path)]
        records: List[RuleRecord] = []

        for path in sorted(rule_files):
            rel_path = path.relative_to(self.rules_root).as_posix()
            top_level = rel_path.split("/", 1)[0]
            language_family = self._normalize_language_family(top_level)

            try:
                doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
            except Exception as exc:
                logger.debug("[SemgrepRuleIndexer] Failed to parse %s: %s", path, exc)
                continue

            if not isinstance(doc, dict):
                continue
            rules = doc.get("rules", [])
            if not isinstance(rules, list):
                continue

            for item in rules:
                if not isinstance(item, dict):
                    continue
                rule_id = str(item.get("id", "")).strip()
                if not rule_id:
                    continue
                metadata = item.get("metadata", {}) if isinstance(item.get("metadata", {}), dict) else {}
                record = RuleRecord(
                    rule_id=rule_id,
                    rule_path=rel_path,
                    top_level=top_level,
                    language_family=language_family,
                    languages=self._to_list(item.get("languages")),
                    severity=str(item.get("severity", "UNKNOWN")).upper(),
                    mode=str(item.get("mode", "pattern")),
                    category=str(metadata.get("category", "")).lower(),
                    subcategory=self._to_list(metadata.get("subcategory")),
                    technology=self._to_list(metadata.get("technology")),
                    cwe=self._to_list(metadata.get("cwe")),
                    owasp=self._to_list(metadata.get("owasp")),
                    references=self._to_list(metadata.get("references")),
                    source_rule_url=str(metadata.get("source-rule-url", "")),
                    likelihood=str(metadata.get("likelihood", "")).upper(),
                    impact=str(metadata.get("impact", "")).upper(),
                    confidence=str(metadata.get("confidence", "")).upper(),
                )
                records.append(record)

        return RuleIndex(
            generated_at_utc=datetime.now(timezone.utc).isoformat(),
            rules_root=str(self.rules_root),
            repo_commit_sha=self._git_sha(self.rules_root),
            total_files_scanned=len(rule_files),
            total_rules_indexed=len(records),
            records=records,
        )

    def build_to_file(self, output_file: Path) -> RuleIndex:
        index = self.build()
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(json.dumps(index.to_dict(), indent=2), encoding="utf-8")
        return index

    def _is_rule_file(self, path: Path) -> bool:
        if not path.is_file():
            return False
        if path.suffix.lower() not in RULE_FILE_SUFFIXES:
            return False
        rel = path.relative_to(self.rules_root).as_posix()
        if any(part in IGNORED_PATH_PARTS for part in rel.split("/")):
            return False
        if any(marker in path.name for marker in IGNORED_FILENAME_SUBSTRINGS):
            return False
        if path.name in {"template.yaml", ".pre-commit-config.yaml"}:
            return False
        return True

    @staticmethod
    def _normalize_language_family(top_level: str) -> str:
        if top_level in {"javascript", "typescript"}:
            return "javascript"
        if top_level in {"yml", "yaml"}:
            return "yaml"
        return top_level

    @staticmethod
    def _to_list(value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(item) for item in value if item is not None]
        return [str(value)]

    @staticmethod
    def _git_sha(root: Path) -> str:
        try:
            result = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            )
            return result.stdout.strip()
        except Exception:
            return ""
