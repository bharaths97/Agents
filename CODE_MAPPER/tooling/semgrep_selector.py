from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Set

from config import settings

from .semgrep_rule_indexer import RuleRecord

SECURITY_SUBCATEGORIES = {"vuln", "audit", "secure default"}


@dataclass
class RuleSelectionResult:
    selected_rules: List[RuleRecord]
    selected_rule_paths: List[Path]
    rationale: Dict[str, int]


def select_rules_for_repo(
    records: List[RuleRecord],
    scan,
    rules_root: Path,
) -> RuleSelectionResult:
    target_families = _language_families(scan.detected_languages)
    tech_tokens = set(scan.detected_frameworks + scan.detected_infra + list(target_families))

    selected: List[RuleRecord] = []
    buckets = defaultdict(int)

    for record in records:
        if not _is_security_or_audit(record):
            continue

        include_reason = _inclusion_reason(record, target_families, tech_tokens)
        if include_reason:
            selected.append(record)
            buckets[include_reason] += 1

    selected = _dedupe(selected)
    if len(selected) > settings.semgrep_max_rules:
        selected = selected[: settings.semgrep_max_rules]
        buckets["cap_applied"] = 1

    selected_paths = sorted({rules_root / record.rule_path for record in selected})
    return RuleSelectionResult(
        selected_rules=selected,
        selected_rule_paths=selected_paths,
        rationale=dict(buckets),
    )


def _is_security_or_audit(record: RuleRecord) -> bool:
    if record.category == "security":
        return True
    return bool(set(record.subcategory).intersection(SECURITY_SUBCATEGORIES))


def _inclusion_reason(
    record: RuleRecord,
    target_families: Set[str],
    tech_tokens: Set[str],
) -> str:
    path = record.rule_path
    path_l = path.lower()

    if path_l.startswith("generic/secrets/"):
        return "generic_secrets"
    if path_l.startswith("problem-based-packs/"):
        if tech_tokens.intersection(set(record.technology)):
            return "problem_pack_technology_match"
        if any(token in path_l for token in tech_tokens):
            return "problem_pack_path_match"

    if record.top_level == "generic":
        if tech_tokens.intersection(set(record.technology)):
            return "generic_tech_match"
        return "generic_security"

    if record.language_family in target_families or record.top_level in target_families:
        return "language_family_match"

    if tech_tokens.intersection(set(record.technology)):
        return "technology_match"

    if any(token in path_l for token in tech_tokens):
        return "path_token_match"

    return ""


def _language_families(detected_languages: Dict[str, int]) -> Set[str]:
    family_map = {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
        ".go": "go",
        ".rb": "ruby",
        ".php": "php",
        ".cs": "csharp",
        ".rs": "rust",
        ".kt": "kotlin",
        ".swift": "swift",
        ".c": "c",
        ".cc": "c",
        ".cpp": "c",
        ".h": "c",
        ".hpp": "c",
    }
    families = set()
    for ext in detected_languages:
        mapped = family_map.get(ext)
        if mapped:
            families.add(mapped)
    if "typescript" in families:
        families.add("javascript")
    return families


def _dedupe(records: Iterable[RuleRecord]) -> List[RuleRecord]:
    seen = set()
    result: List[RuleRecord] = []
    for record in records:
        key = (record.rule_id, record.rule_path)
        if key in seen:
            continue
        seen.add(key)
        result.append(record)
    return result
