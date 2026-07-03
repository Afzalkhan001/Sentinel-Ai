from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import secrets_store
from ..config import settings
from ..db import get_db
from ..models_db import RegisteredModel
from ..providers.registry import SUPPORTED_PROVIDERS, get_provider
from ..schemas import ModelCreate, ModelOut, ModelTestResult

router = APIRouter(prefix="/api/models", tags=["models"])


@router.get("", response_model=list[ModelOut])
def list_models(db: Session = Depends(get_db)):
    return db.query(RegisteredModel).order_by(RegisteredModel.created_at.asc()).all()


@router.post("", response_model=ModelOut, status_code=201)
def create_model(payload: ModelCreate, db: Session = Depends(get_db)):
    provider = payload.provider.lower()
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(400, f"Unsupported provider. Supported: {SUPPORTED_PROVIDERS}")

    request_config = None
    if provider == "custom":
        if not payload.base_url:
            raise HTTPException(400, "Custom endpoint requires a base_url (the endpoint URL).")
        if not payload.request_config:
            raise HTTPException(400, "Custom endpoint requires request_config (body_template + response_path).")
        request_config = payload.request_config.model_dump()

    model = RegisteredModel(
        name=payload.name,
        provider=provider,
        model_name=payload.model_name or ("custom-endpoint" if provider == "custom" else ""),
        base_url=payload.base_url,
        key_last4=secrets_store.last4(payload.api_key),
        is_default=False,
        request_config=request_config,
    )
    db.add(model)
    db.commit()
    db.refresh(model)

    if payload.api_key:
        secrets_store.set_key(model.id, payload.api_key)
    return model


@router.get("/{model_id}", response_model=ModelOut)
def get_model(model_id: str, db: Session = Depends(get_db)):
    model = db.get(RegisteredModel, model_id)
    if not model:
        raise HTTPException(404, "Model not found")
    return model


@router.delete("/{model_id}", status_code=204)
def delete_model(model_id: str, db: Session = Depends(get_db)):
    model = db.get(RegisteredModel, model_id)
    if not model:
        raise HTTPException(404, "Model not found")
    if model.is_default:
        raise HTTPException(400, "Cannot delete the default model")
    db.delete(model)
    db.commit()
    secrets_store.delete_key(model_id)


@router.post("/{model_id}/test", response_model=ModelTestResult)
async def test_model(model_id: str, db: Session = Depends(get_db)):
    model = db.get(RegisteredModel, model_id)
    if not model:
        raise HTTPException(404, "Model not found")

    api_key = settings.groq_api_key if model.is_default else secrets_store.get_key(model_id)
    provider = get_provider(model.provider, model.model_name, api_key, model.base_url, model.request_config)
    completion = await provider.complete("Reply with the single word: pong", max_tokens=16)
    return ModelTestResult(
        ok=completion.error is None and bool(completion.text.strip()),
        latency_ms=completion.latency_ms,
        sample=completion.text.strip()[:120] or None,
        error=completion.error,
    )
