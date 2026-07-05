from datetime import datetime

from pydantic import BaseModel


# ---- Models ----
class RequestConfig(BaseModel):
    method: str = "POST"
    headers: dict[str, str] = {}
    body_template: str = '{"prompt": "{{prompt}}"}'
    response_path: str = ""


class ModelCreate(BaseModel):
    name: str
    provider: str
    model_name: str = ""
    api_key: str | None = None
    base_url: str | None = None
    request_config: RequestConfig | None = None  # required for provider="custom"


class ModelOut(BaseModel):
    id: str
    name: str
    provider: str
    model_name: str
    base_url: str | None = None
    key_last4: str | None = None
    is_default: bool = False
    request_config: dict | None = None
    created_at: datetime

    class Config:
        from_attributes = True


class ModelTestResult(BaseModel):
    ok: bool
    latency_ms: int
    sample: str | None = None
    error: str | None = None


# ---- Attacks ----
class SuccessRuleOut(BaseModel):
    type: str
    patterns: list[str] = []
    refusal_markers: list[str] = []


class AttackOut(BaseModel):
    id: str
    category: str
    name: str
    owasp: str
    severity: str
    description: str
    prompt_template: str
    success: SuccessRuleOut
    tags: list[str] = []


# ---- Runs ----
class RunCreate(BaseModel):
    model_id: str
    attack_ids: list[str] | None = None  # None or empty => all attacks
    use_llm_judge: bool = False          # LLM-judge tie-breaker on ambiguous verdicts
    samples: int = 1                     # run each attack N times and vote (reliability mode)
    judge_model_id: str | None = None    # which model judges (defaults to the target)


class RunOut(BaseModel):
    id: str
    model_id: str
    model_label: str | None = None
    status: str
    created_at: datetime
    completed_at: datetime | None = None
    total: int
    succeeded_count: int
    inconclusive_count: int | None = 0
    score: int | None = None
    risk_level: str | None = None
    attack_success_pct: int | None = None
    owasp_breakdown: list | None = None
    recommendations: list | None = None
    error: str | None = None

    class Config:
        from_attributes = True


# ---- Repo / Web scans ----
class RepoScanCreate(BaseModel):
    repo_url: str
    use_ai: bool = False
    reviewer_model_id: str | None = None


class WebScanCreate(BaseModel):
    target_url: str
    authorized: bool = False
    use_ai: bool = False
    reviewer_model_id: str | None = None


class ScanOut(BaseModel):
    id: str
    status: str
    score: int | None = None
    risk_level: str | None = None
    total_findings: int = 0
    severity_counts: dict | None = None
    category_breakdown: list | None = None
    findings: list | None = None
    stats: dict | None = None
    error: str | None = None
    created_at: datetime
    completed_at: datetime | None = None
    # target fields (one will be set depending on scan type)
    repo_url: str | None = None
    target_url: str | None = None
    use_ai: bool = False
    authorized: bool = False

    class Config:
        from_attributes = True


# ---- Red Team ----
class RedTeamCreate(BaseModel):
    target_model_id: str
    objective: str
    max_rounds: int = 5
    attacker_model_id: str | None = None  # defaults to the default model


class RedTeamOut(BaseModel):
    id: str
    target_model_id: str
    target_label: str | None = None
    attacker_model_id: str | None = None
    objective: str
    max_rounds: int
    status: str
    achieved: bool
    rounds_used: int
    transcript: list | None = None
    summary: str | None = None
    error: str | None = None
    created_at: datetime
    completed_at: datetime | None = None

    class Config:
        from_attributes = True


class ResultOut(BaseModel):
    id: str
    attack_id: str
    attack_name: str | None = None
    category: str | None = None
    owasp: str | None = None
    severity: str | None = None
    prompt_sent: str | None = None
    response_text: str | None = None
    succeeded: bool
    detection_method: str | None = None
    confidence: float | None = None
    latency_ms: int | None = None
    error: str | None = None

    class Config:
        from_attributes = True
