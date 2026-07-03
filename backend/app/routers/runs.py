from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from ..attacks.loader import load_attacks
from ..db import get_db
from ..engine.runner import execute_run, resolve_provider_cfg
from ..models_db import RegisteredModel, Result, Run
from ..schemas import ResultOut, RunCreate, RunOut

router = APIRouter(prefix="/api/runs", tags=["runs"])


def _to_run_out(run: Run) -> RunOut:
    out = RunOut.model_validate(run)
    if run.total:
        out.attack_success_pct = round(100 * run.succeeded_count / run.total)
    return out


@router.post("", response_model=RunOut, status_code=201)
def create_run(payload: RunCreate, background: BackgroundTasks, db: Session = Depends(get_db)):
    model = db.get(RegisteredModel, payload.model_id)
    if not model:
        raise HTTPException(404, "Model not found")

    all_ids = [a.id for a in load_attacks()]
    attack_ids = payload.attack_ids or all_ids
    attack_ids = [i for i in attack_ids if i in all_ids]
    if not attack_ids:
        raise HTTPException(400, "No valid attacks selected")

    cfg = resolve_provider_cfg(model)
    if not cfg.get("api_key") and model.provider != "ollama":
        raise HTTPException(400, "No API key available for this model. Re-register it with a key.")

    run = Run(
        model_id=model.id,
        model_label=f"{model.name} ({model.model_name})",
        status="running",
        total=len(attack_ids),
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    background.add_task(execute_run, run.id, cfg, attack_ids)
    return _to_run_out(run)


@router.get("", response_model=list[RunOut])
def list_runs(db: Session = Depends(get_db)):
    runs = db.query(Run).order_by(Run.created_at.desc()).all()
    return [_to_run_out(r) for r in runs]


@router.get("/{run_id}", response_model=RunOut)
def get_run(run_id: str, db: Session = Depends(get_db)):
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    return _to_run_out(run)


@router.get("/{run_id}/results", response_model=list[ResultOut])
def get_results(run_id: str, db: Session = Depends(get_db)):
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    return db.query(Result).filter(Result.run_id == run_id).all()
