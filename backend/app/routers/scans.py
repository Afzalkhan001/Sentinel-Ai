import re

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import get_db
from ..engine.repo_scanner import scan_repo
from ..engine.runner import resolve_provider_cfg
from ..engine.web_scanner import scan_web
from ..models_db import RegisteredModel, RepoScan, WebScan
from ..schemas import RepoScanCreate, ScanOut, WebScanCreate

router = APIRouter(prefix="/api/scan", tags=["scanners"])


def _reviewer_cfg(db: Session, reviewer_model_id: str | None):
    """Resolve the LLM used for optional AI review (falls back to the default model)."""
    model = None
    if reviewer_model_id:
        model = db.get(RegisteredModel, reviewer_model_id)
    if not model:
        model = db.query(RegisteredModel).filter(RegisteredModel.is_default.is_(True)).first()
    return resolve_provider_cfg(model) if model else None


# ---------------- Repo ----------------
@router.post("/repo", response_model=ScanOut, status_code=201)
def create_repo_scan(payload: RepoScanCreate, background: BackgroundTasks, db: Session = Depends(get_db)):
    url = payload.repo_url.strip()
    if not re.match(r"^(https?://|git@)", url):
        raise HTTPException(400, "Provide a valid git/HTTP(S) repository URL.")

    reviewer = _reviewer_cfg(db, payload.reviewer_model_id) if payload.use_ai else None
    scan = RepoScan(repo_url=url, use_ai=payload.use_ai, status="running")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background.add_task(scan_repo, scan.id, url, payload.use_ai, reviewer)
    return scan


@router.get("/repo", response_model=list[ScanOut])
def list_repo_scans(db: Session = Depends(get_db)):
    return db.query(RepoScan).order_by(RepoScan.created_at.desc()).all()


@router.get("/repo/{scan_id}", response_model=ScanOut)
def get_repo_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(RepoScan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


# ---------------- Web ----------------
@router.post("/web", response_model=ScanOut, status_code=201)
def create_web_scan(payload: WebScanCreate, background: BackgroundTasks, db: Session = Depends(get_db)):
    url = payload.target_url.strip()
    if not url or " " in url:
        raise HTTPException(400, "Provide a valid website URL.")

    reviewer = _reviewer_cfg(db, payload.reviewer_model_id) if payload.use_ai else None
    scan = WebScan(target_url=url, authorized=payload.authorized, use_ai=payload.use_ai, status="running")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background.add_task(scan_web, scan.id, url, payload.authorized, payload.use_ai, reviewer)
    return scan


@router.get("/web", response_model=list[ScanOut])
def list_web_scans(db: Session = Depends(get_db)):
    return db.query(WebScan).order_by(WebScan.created_at.desc()).all()


@router.get("/web/{scan_id}", response_model=ScanOut)
def get_web_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(WebScan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan
