"""
Pydantic schemas for all agent I/O.
Schemas are derived directly from the output format sections in code_scanner_prompts.py.
The validator uses these to enforce anti-hallucination constraints at parse time.
"""
from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Agent 1a — Context & Domain Reader
# ---------------------------------------------------------------------------

class CtfFlagHit(BaseModel):
    pattern_family: Literal["FLAG", "CTF", "HTB", "THM", "PICOCTF", "DUCTF", "OTHER"]
    match: str
    file: str
    line_start: int
    line_end: int
    snippet: str
    confidence: Literal["HIGH", "MEDIUM", "LOW"]
    likely_placeholder: bool
    notes: str


class UserType(BaseModel):
    type: str
    trust_level: Literal["UNTRUSTED", "PARTIALLY_TRUSTED", "TRUSTED"]
    description: str


class DataHandled(BaseModel):
    data_type: str
    sensitivity: Literal["PII", "PHI", "CREDENTIAL", "FINANCIAL", "INTERNAL", "PUBLIC"]
    notes: str


class DeploymentContext(BaseModel):
    environment: Literal["cloud", "on-prem", "hybrid", "unknown"]
    publicly_exposed: bool
    authentication_mechanism: str
    notable_infrastructure: List[str]


class Agent1aOutput(BaseModel):
    domain: str
    domain_risk_tier: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    domain_risk_reasoning: str
    regulatory_context: List[str]
    user_types: List[UserType]
    data_handled: List[DataHandled]
    component_intent_map: Dict[str, str]
    intended_security_posture: str
    deployment_context: DeploymentContext
    test_derived_assumptions: List[str]
    notable_developer_comments: List[str]
    flags: List[str]
    ctf_flag_hits: List[CtfFlagHit] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Agent 1b — Code Semantics Analyst
# ---------------------------------------------------------------------------

class SemanticEntry(BaseModel):
    intended: str
    actual: str
    diverges: bool
    divergence_note: Optional[str] = None


class InsecurePracticeFinding(BaseModel):
    id: str
    file: str
    line_start: int
    line_end: int
    snippet: str
    category: Literal[
        "BUFFER_OVERFLOW", "INTEGER_OVERFLOW", "USE_AFTER_FREE", "DOUBLE_FREE",
        "FORMAT_STRING", "WEAK_CRYPTO", "INSECURE_DEFAULT", "INSECURE_DESERIALIZATION",
        "MISSING_AUTH", "IDOR", "COMMENTED_SECURITY", "RACE_CONDITION",
        "CREDENTIAL_EXPOSURE", "INSECURE_PRACTICE",
        "SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL", "XSS",
        "SSRF", "SERVER_SIDE_REQUEST_FORGERY", "XXE", "OPEN_REDIRECT",
        "INSECURE_REDIRECT", "MASS_ASSIGNMENT", "PROTOTYPE_POLLUTION",
        "OTHER",
    ]
    cwe: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    description: str
    exploit_scenario: str
    adversarial_check: str
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_reasoning: List[str]
    false_positive_risk: Literal["LOW", "MEDIUM", "HIGH"]
    false_positive_notes: str

    @field_validator("confidence_reasoning")
    @classmethod
    def min_two_reasons(cls, v: List[str]) -> List[str]:
        if len(v) < 1:
            raise ValueError("confidence_reasoning must have at least one entry")
        return v


class Agent1bOutput(BaseModel):
    semantics_map: Dict[str, SemanticEntry]
    insecure_practice_findings: List[InsecurePracticeFinding]
    ctf_flag_hits: List[CtfFlagHit] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Agent 1c — Data & Logging Classifier
# ---------------------------------------------------------------------------

class DataTaxonomyEntry(BaseModel):
    classification: Literal["PII", "PHI", "CREDENTIAL", "FINANCIAL", "INTERNAL", "PUBLIC"]
    reasoning: str
    domain_context_used: bool = False


class LoggingFinding(BaseModel):
    id: str
    file: str
    line: int
    snippet: str
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL", "UNKNOWN"]
    logged_expression: str
    logged_data_classification: Literal[
        "PII", "PHI", "CREDENTIAL", "FINANCIAL", "INTERNAL", "PUBLIC", "MIXED"
    ]

    @field_validator("logged_data_classification", mode="before")
    @classmethod
    def coerce_classification(cls, v: Any) -> str:
        # LLM sometimes returns pipe-separated combos like "PII | PUBLIC"; pick most sensitive
        _SENSITIVITY = ["CREDENTIAL", "PHI", "PII", "FINANCIAL", "INTERNAL", "MIXED", "PUBLIC"]
        if isinstance(v, str) and ("|" in v or "/" in v or "," in v):
            import re
            parts = [p.strip() for p in re.split(r"[|/,]", v)]
            for label in _SENSITIVITY:
                if label in parts:
                    return label
            return "MIXED"
        return v
    exposure_mechanism: Literal[
        "DIRECT_VALUE", "OBJECT_SERIALIZATION", "EXCEPTION_SCOPE",
        "FORMAT_STRING", "REQUEST_OBJECT", "OTHER",
    ]
    risk_description: str
    production_risk: Literal["HIGH", "MEDIUM", "LOW"]
    production_risk_reasoning: str
    adversarial_check: str
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_reasoning: List[str]

    @field_validator("confidence_reasoning")
    @classmethod
    def min_two_reasons(cls, v: List[str]) -> List[str]:
        if len(v) < 1:
            raise ValueError("confidence_reasoning must have at least one entry")
        return v


class Agent1cOutput(BaseModel):
    data_taxonomy: Dict[str, DataTaxonomyEntry]
    logging_findings: List[LoggingFinding]
    ctf_flag_hits: List[CtfFlagHit] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Agent 1d — Terrain Synthesizer (per-file terrain + threat model)
# ---------------------------------------------------------------------------

class Source(BaseModel):
    variable: str
    line: int
    type: Literal[
        "http_param", "env_var", "file_read", "db_result",
        "ipc", "deserialization", "other"
    ]
    trust_level: Literal["UNTRUSTED", "PARTIALLY_TRUSTED", "TRUSTED"]
    data_classification: Literal[
        "PII", "PHI", "CREDENTIAL", "FINANCIAL", "INTERNAL", "PUBLIC"
    ]
    notes: Optional[str] = None


class Sink(BaseModel):
    variable: str
    line: int
    type: Literal[
        "sql_exec", "shell_cmd", "html_render", "file_write",
        "eval", "network_egress", "deserialization", "other"
    ]
    sink_fn: str
    notes: Optional[str] = None


class AdjustedPracticeFinding(BaseModel):
    source_agent: str
    original_id: str
    severity_original: str
    severity_adjusted: str
    severity_adjustment_reason: str
    finding: Dict[str, Any]


class AdjustedLoggingFinding(BaseModel):
    source_agent: str
    original_id: str
    production_risk_adjusted: str
    finding: Dict[str, Any]


class ConflictEntry(BaseModel):
    conflict_id: str
    description: str
    agent_1a_says: Optional[str] = None
    agent_1b_says: Optional[str] = None
    agent_1c_says: Optional[str] = None
    security_implication: str
    resolution: str = "UNRESOLVED — defer to Agent 1e"


class IntentDivergence(BaseModel):
    function: str
    intended: str
    actual: str
    security_implication: str


class PriorityFinding(BaseModel):
    rank: int
    finding_id: str
    type: Literal["INSECURE_PRACTICE", "LOGGING_RISK", "CONFLICT", "INTENT_DIVERGENCE"]
    priority_score: float = Field(ge=0.0, le=10.0)
    priority_reasoning: str


class TerrainObject(BaseModel):
    file: str
    domain_context: str
    domain_risk_tier: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    sources: List[Source]
    sinks: List[Sink]
    insecure_practice_findings: List[AdjustedPracticeFinding]
    logging_findings: List[AdjustedLoggingFinding]
    conflicts: List[ConflictEntry]
    intent_divergences: List[IntentDivergence]
    priority_findings: List[PriorityFinding]
    ctf_flag_hits: List[CtfFlagHit] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Threat Model (system-wide, emitted once by Agent 1d)
# ---------------------------------------------------------------------------

class Asset(BaseModel):
    asset_id: str
    name: str
    classification: Literal["PII", "PHI", "CREDENTIAL", "FINANCIAL", "INTERNAL", "PUBLIC"]
    location: str
    value: Literal["HIGH", "MEDIUM", "LOW"]
    value_reasoning: str


class TrustBoundary(BaseModel):
    boundary_id: str
    name: str
    from_zone: str
    to_zone: str
    crossing_components: List[str]
    data_crossing: List[str]


class AttackSurface(BaseModel):
    surface_id: str
    component: str
    entry_point: str
    trust_boundary_crossed: str
    accepts_untrusted_input: bool
    input_type: Literal["http_param", "file_upload", "env_var", "ipc", "sql_exec", "db_query", "message_queue", "other"]
    exposed_assets: List[str]


class StrideEntry(BaseModel):
    component: str
    threat_category: Literal[
        "Spoofing", "Tampering", "Repudiation",
        "Information Disclosure", "Denial of Service", "Elevation of Privilege"
    ]
    threat_id: str
    threat_description: str
    affected_assets: List[str]
    attack_vector: str
    likelihood: Literal["HIGH", "MEDIUM", "LOW"]
    likelihood_reasoning: str
    impact: Literal["HIGH", "MEDIUM", "LOW"]
    impact_reasoning: str
    risk_score: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    @field_validator("impact", mode="before")
    @classmethod
    def coerce_impact(cls, v: Any) -> str:
        # LLM sometimes returns CRITICAL for impact; map to HIGH (CRITICAL is only valid for risk_score)
        if v == "CRITICAL":
            return "HIGH"
        return v
    existing_controls: List[str]
    control_adequacy: Literal["ADEQUATE", "PARTIAL", "NONE"]
    related_terrain_sources: List[str]
    related_terrain_sinks: List[str]


class ThreatScenario(BaseModel):
    scenario_id: str
    rank: int
    title: str
    narrative: str
    threat_ids: List[str]
    entry_point: str
    targeted_assets: List[str]
    risk_score: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    taint_paths_to_investigate: List[str]


class ThreatModel(BaseModel):
    methodology: str = "STRIDE"
    domain: str
    domain_risk_tier: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    regulatory_context: List[str]
    assets: List[Asset]
    trust_boundaries: List[TrustBoundary]
    attack_surface: List[AttackSurface]
    stride_analysis: List[StrideEntry]
    prioritized_threat_scenarios: List[ThreatScenario]


class CtfArtifacts(BaseModel):
    summary: str
    hits: List[CtfFlagHit]


class ThreatModelOutput(BaseModel):
    ctf_artifacts: CtfArtifacts = Field(default_factory=lambda: CtfArtifacts(summary="", hits=[]))
    threat_model: ThreatModel


# ---------------------------------------------------------------------------
# Agent 1e — Taint Tracer
# ---------------------------------------------------------------------------

class TransformationStep(BaseModel):
    step: int
    line: int
    operation: str
    sanitization_applied: bool
    sanitization_notes: str
    crosses_file_boundary: bool = False
    target_file: Optional[str] = None
    target_function: Optional[str] = None
    parameter_mapping: Dict[str, str] = Field(default_factory=dict)


class ReachesSink(BaseModel):
    sink_variable: str
    sink_line: int
    sink_fn: str
    sink_type: str
    path_is_reachable: bool
    reachability_notes: str


class FlowMapEntry(BaseModel):
    source_variable: str
    source_line: int
    source_type: str
    data_classification: str
    transformation_chain: List[TransformationStep]
    reaches_sinks: List[ReachesSink]
    linked_call_chains: List[Dict[str, Any]] = Field(default_factory=list)


class SanitizationInfo(BaseModel):
    exists: bool
    correct: bool
    sufficient: bool
    details: str


class TaintFinding(BaseModel):
    id: str
    source: Dict[str, Any]
    sink: Dict[str, Any]
    taint_path: List[str]
    sanitization: SanitizationInfo
    vulnerability: str
    cwe: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    domain_risk_context: str
    linked_threat_scenario: Optional[str] = None
    linked_stride_threat: Optional[str] = None
    exploit_scenario: str
    verification_1_reachability: str
    verification_2_sanitization: str
    verification_3_adversarial: str
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_reasoning: List[str]
    false_positive_risk: Literal["LOW", "MEDIUM", "HIGH"]
    false_positive_notes: str
    remediation: str
    snippet: Optional[str] = None
    crosses_file_boundary: bool = False
    boundary_hops: List[Dict[str, Any]] = Field(default_factory=list)
    chain_length: Optional[int] = None

    @field_validator("confidence_reasoning")
    @classmethod
    def min_two_reasons(cls, v: List[str]) -> List[str]:
        if len(v) < 1:
            raise ValueError("confidence_reasoning must have at least one entry")
        return v


class ConflictResolution(BaseModel):
    conflict_id: str
    resolution: str
    evidence: str


class CleanPath(BaseModel):
    source_variable: str
    sink_fn: str
    reason_clean: str


class LowConfidenceObservation(BaseModel):
    source_variable: str
    sink_fn: str
    note: str
    confidence: float


class Agent1eOutput(BaseModel):
    file: str
    pass1_flow_map: List[FlowMapEntry] = Field(default_factory=list)
    taint_findings: List[TaintFinding]
    conflict_resolutions: List[ConflictResolution] = Field(default_factory=list)
    clean_paths: List[CleanPath] = Field(default_factory=list)
    low_confidence_observations: List[LowConfidenceObservation] = Field(default_factory=list)
