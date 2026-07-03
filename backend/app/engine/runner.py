import asyncio
from datetime import datetime, timezone

from ..attacks.loader import Attack, load_attacks
from ..config import settings
from ..db import SessionLocal
from ..models_db import RegisteredModel, Result, Run
from ..providers.registry import get_provider
from .. import secrets_store
from .evaluator import evaluate
from .scoring import compute


async def _run_one(provider, attack: Attack, sem: asyncio.Semaphore) -> dict:
    async with sem:
        completion = await provider.complete(attack.prompt_template)

    if completion.error:
        return {
            "attack": attack,
            "response_text": "",
            "succeeded": False,
            "detection_method": "error",
            "confidence": 0.0,
            "latency_ms": completion.latency_ms,
            "error": completion.error,
        }

    succeeded, method, confidence = evaluate(attack, completion.text)
    return {
        "attack": attack,
        "response_text": completion.text,
        "succeeded": succeeded,
        "detection_method": method,
        "confidence": confidence,
        "latency_ms": completion.latency_ms,
        "error": None,
    }


async def execute_run(run_id: str, provider_cfg: dict, attack_ids: list[str]) -> None:
    """Background task: run every selected attack, evaluate, score, persist."""
    all_attacks = {a.id: a for a in load_attacks()}
    attacks = [all_attacks[i] for i in attack_ids if i in all_attacks]

    provider = get_provider(
        provider_cfg["provider"],
        provider_cfg["model_name"],
        provider_cfg.get("api_key"),
        provider_cfg.get("base_url"),
        provider_cfg.get("request_config"),
    )

    sem = asyncio.Semaphore(settings.run_concurrency)
    outcomes = await asyncio.gather(*[_run_one(provider, a, sem) for a in attacks])

    scoring_input = [
        {
            "severity": o["attack"].severity,
            "category": o["attack"].category,
            "owasp": o["attack"].owasp,
            "attack_id": o["attack"].id,
            "succeeded": o["succeeded"],
        }
        for o in outcomes
    ]
    summary = compute(scoring_input)

    db = SessionLocal()
    try:
        run = db.get(Run, run_id)
        if run is None:
            return
        for o in outcomes:
            a = o["attack"]
            db.add(
                Result(
                    run_id=run_id,
                    attack_id=a.id,
                    attack_name=a.name,
                    category=a.category,
                    owasp=a.owasp,
                    severity=a.severity,
                    prompt_sent=a.prompt_template,
                    response_text=o["response_text"],
                    succeeded=o["succeeded"],
                    detection_method=o["detection_method"],
                    confidence=o["confidence"],
                    latency_ms=o["latency_ms"],
                    error=o["error"],
                )
            )
        run.status = "completed"
        run.completed_at = datetime.now(timezone.utc)
        run.total = summary["total"]
        run.succeeded_count = summary["succeeded_count"]
        run.score = summary["score"]
        run.risk_level = summary["risk_level"]
        run.owasp_breakdown = summary["owasp_breakdown"]
        run.recommendations = summary["recommendations"]
        db.commit()
    except Exception as e:  # noqa: BLE001
        db.rollback()
        run = db.get(Run, run_id)
        if run is not None:
            run.status = "failed"
            run.error = str(e)
            db.commit()
    finally:
        db.close()


def resolve_provider_cfg(model: RegisteredModel) -> dict:
    """Build the provider config (including the live API key from the vault)."""
    if model.is_default:
        api_key = settings.groq_api_key
    else:
        api_key = secrets_store.get_key(model.id)
    return {
        "provider": model.provider,
        "model_name": model.model_name,
        "base_url": model.base_url,
        "api_key": api_key,
        "request_config": model.request_config,
    }
