import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.types import JSON

from .db import Base


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> datetime:
    return datetime.now(timezone.utc)


class RegisteredModel(Base):
    __tablename__ = "registered_models"

    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String, nullable=False)
    provider = Column(String, nullable=False)  # openai|groq|openrouter|deepseek|ollama|gemini|anthropic|huggingface
    model_name = Column(String, nullable=False)
    base_url = Column(String, nullable=True)
    key_last4 = Column(String, nullable=True)
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime, default=_now)
    # For provider="custom": {method, headers, body_template, response_path}
    request_config = Column(JSON, nullable=True)


class Run(Base):
    __tablename__ = "runs"

    id = Column(String, primary_key=True, default=_uuid)
    model_id = Column(String, nullable=False)
    model_label = Column(String, nullable=True)
    status = Column(String, default="pending")  # pending|running|completed|failed
    created_at = Column(DateTime, default=_now)
    completed_at = Column(DateTime, nullable=True)

    total = Column(Integer, default=0)
    succeeded_count = Column(Integer, default=0)
    score = Column(Integer, nullable=True)
    risk_level = Column(String, nullable=True)
    owasp_breakdown = Column(JSON, nullable=True)
    recommendations = Column(JSON, nullable=True)
    error = Column(Text, nullable=True)

    results = relationship("Result", back_populates="run", cascade="all, delete-orphan")


class RedTeamSession(Base):
    __tablename__ = "redteam_sessions"

    id = Column(String, primary_key=True, default=_uuid)
    target_model_id = Column(String, nullable=False)
    target_label = Column(String, nullable=True)
    attacker_model_id = Column(String, nullable=True)
    objective = Column(Text, nullable=False)
    max_rounds = Column(Integer, default=5)

    status = Column(String, default="running")  # running|completed|failed
    achieved = Column(Boolean, default=False)
    rounds_used = Column(Integer, default=0)
    transcript = Column(JSON, nullable=True)  # list of round dicts
    summary = Column(Text, nullable=True)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=_now)
    completed_at = Column(DateTime, nullable=True)


class Result(Base):
    __tablename__ = "results"

    id = Column(String, primary_key=True, default=_uuid)
    run_id = Column(String, ForeignKey("runs.id"), nullable=False)
    attack_id = Column(String, nullable=False)
    attack_name = Column(String, nullable=True)
    category = Column(String, nullable=True)
    owasp = Column(String, nullable=True)
    severity = Column(String, nullable=True)

    prompt_sent = Column(Text, nullable=True)
    response_text = Column(Text, nullable=True)
    succeeded = Column(Boolean, default=False)
    detection_method = Column(String, nullable=True)
    confidence = Column(Float, nullable=True)
    latency_ms = Column(Integer, nullable=True)
    error = Column(Text, nullable=True)

    run = relationship("Run", back_populates="results")
