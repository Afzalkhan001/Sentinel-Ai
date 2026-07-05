import asyncio
from datetime import datetime, timezone

from ..attacks.loader import Attack, load_attacks
from ..config import settings
from ..db import SessionLocal
from ..models_db import RegisteredModel, Result, Run
from ..providers.registry import get_provider
from .. import secrets_store
from .evaluator import evaluate
from .judge import llm_judge
from .scoring import compute

AMBIGUOUS = 0.65  # verdicts below this confidence get escalated (LLM judge) when enabled


async def _evaluate_attack(provider, attack: Attack, samples: int, sem: asyncio.Semaphore,
                           use_llm_judge: bool, judge_cfg: dict | None) -> dict:
    """Run one attack `samples` times, vote, and optionally escalate to an LLM judge."""
    completions = []
    async with sem:
        for _ in range(max(1, samples)):
            completions.append(await provider.complete(attack.prompt_template))

    ok = [c for c in completions if not c.error]
    if not ok:  # every sample errored -> inconclusive, excluded from scoring
        err = completions[0].error if completions else "no response"
        return {"attack": attack, "response_text": "", "succeeded": False, "errored": True,
                "detection_method": "error", "confidence": 0.0,
                "latency_ms": completions[0].latency_ms if completions else 0, "error": err}

    verdicts = [(evaluate(attack, c.text), c) for c in ok]
    # Security semantics: a breach in ANY sample means the guardrail is breakable.
    any_succeeded = any(v[0][0] for v in verdicts)
    all_agree = len({v[0][0] for v in verdicts}) == 1
    # representative output: pick one matching the final verdict
    rep = next((c for (v, c) in verdicts if v[0] == any_succeeded), ok[0])
    base_conf = max(v[0][2] for v in verdicts)
    confidence = base_conf if all_agree else 0.55
    method = verdicts[0][0][1] + (f" x{len(ok)}" if len(ok) > 1 else "")
    succeeded = any_succeeded

    # Escalate ambiguous verdicts to the LLM judge (opt-in, bounded cost)
    if confidence < AMBIGUOUS and use_llm_judge and judge_cfg and judge_cfg.get("api_key"):
        verdict = await llm_judge(judge_cfg, attack, rep.text)
        if verdict is not None:
            succeeded, reason, confidence = verdict
            method = "llm-judge"
            rep = next((c for (v, c) in verdicts if v[0] == succeeded), rep)

    return {"attack": attack, "response_text": rep.text, "succeeded": succeeded, "errored": False,
            "detection_method": method, "confidence": round(confidence, 2),
            "latency_ms": rep.latency_ms, "error": None}


async def execute_run(run_id: str, provider_cfg: dict, attack_ids: list[str],
                      use_llm_judge: bool = False, samples: int = 1, judge_cfg: dict | None = None) -> None:
    all_attacks = {a.id: a for a in load_attacks()}
    attacks = [all_attacks[i] for i in attack_ids if i in all_attacks]

    provider = get_provider(provider_cfg["provider"], provider_cfg["model_name"],
                            provider_cfg.get("api_key"), provider_cfg.get("base_url"),
                            provider_cfg.get("request_config"))

    sem = asyncio.Semaphore(settings.run_concurrency)
    outcomes = await asyncio.gather(*[
        _evaluate_attack(provider, a, samples, sem, use_llm_judge, judge_cfg) for a in attacks
    ])

    scoring_input = [{"severity": o["attack"].severity, "category": o["attack"].category,
                      "owasp": o["attack"].owasp, "attack_id": o["attack"].id,
                      "succeeded": o["succeeded"], "errored": o["errored"]} for o in outcomes]
    summary = compute(scoring_input)

    db = SessionLocal()
    try:
        run = db.get(Run, run_id)
        if run is None:
            return
        for o in outcomes:
            a = o["attack"]
            db.add(Result(
                run_id=run_id, attack_id=a.id, attack_name=a.name, category=a.category,
                owasp=a.owasp, severity=a.severity, prompt_sent=a.prompt_template,
                response_text=o["response_text"], succeeded=o["succeeded"],
                detection_method=o["detection_method"], confidence=o["confidence"],
                latency_ms=o["latency_ms"], error=o["error"],
            ))
        run.status = "completed"
        run.completed_at = datetime.now(timezone.utc)
        run.total = summary["total"]
        run.succeeded_count = summary["succeeded_count"]
        run.inconclusive_count = summary["inconclusive_count"]
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
    api_key = settings.groq_api_key if model.is_default else secrets_store.get_key(model.id)
    return {"provider": model.provider, "model_name": model.model_name, "base_url": model.base_url,
            "api_key": api_key, "request_config": model.request_config}
