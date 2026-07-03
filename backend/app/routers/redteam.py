from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import get_db
from ..engine.redteam import run_redteam
from ..engine.runner import resolve_provider_cfg
from ..models_db import RedTeamSession, RegisteredModel
from ..schemas import RedTeamCreate, RedTeamOut

router = APIRouter(prefix="/api/redteam", tags=["redteam"])


@router.post("", response_model=RedTeamOut, status_code=201)
def create_session(payload: RedTeamCreate, background: BackgroundTasks, db: Session = Depends(get_db)):
    target = db.get(RegisteredModel, payload.target_model_id)
    if not target:
        raise HTTPException(404, "Target model not found")

    attacker_id = payload.attacker_model_id or payload.target_model_id
    attacker = db.get(RegisteredModel, attacker_id)
    if not attacker:
        # Fall back to the default model as attacker
        attacker = db.query(RegisteredModel).filter(RegisteredModel.is_default.is_(True)).first()
    if not attacker:
        raise HTTPException(400, "No attacker model available")

    target_cfg = resolve_provider_cfg(target)
    attacker_cfg = resolve_provider_cfg(attacker)
    if not attacker_cfg.get("api_key") and attacker.provider != "ollama":
        raise HTTPException(400, "Attacker model has no API key. Register a model with a key or set GROQ_API_KEY.")
    if not target_cfg.get("api_key") and target.provider != "ollama":
        raise HTTPException(400, "Target model has no API key.")

    max_rounds = max(1, min(payload.max_rounds, 10))
    session = RedTeamSession(
        target_model_id=target.id,
        target_label=f"{target.name} ({target.model_name})",
        attacker_model_id=attacker.id,
        objective=payload.objective.strip(),
        max_rounds=max_rounds,
        status="running",
        transcript=[],
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    background.add_task(run_redteam, session.id, target_cfg, attacker_cfg, session.objective, max_rounds)
    return session


@router.get("", response_model=list[RedTeamOut])
def list_sessions(db: Session = Depends(get_db)):
    return db.query(RedTeamSession).order_by(RedTeamSession.created_at.desc()).all()


@router.get("/{session_id}", response_model=RedTeamOut)
def get_session(session_id: str, db: Session = Depends(get_db)):
    session = db.get(RedTeamSession, session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    return session
