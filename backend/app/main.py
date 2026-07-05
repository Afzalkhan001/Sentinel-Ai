from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .db import SessionLocal, init_db
from .models_db import RegisteredModel
from .routers import attacks, models, redteam, runs, scans


def _seed_default_model() -> None:
    db = SessionLocal()
    try:
        existing = db.query(RegisteredModel).filter(RegisteredModel.is_default.is_(True)).first()
        if existing:
            return
        db.add(
            RegisteredModel(
                name="Default (Groq free tier)",
                provider=settings.default_provider,
                model_name=settings.default_model_name,
                base_url=settings.groq_base_url,
                key_last4=settings.groq_api_key[-4:] if settings.groq_api_key else None,
                is_default=True,
            )
        )
        db.commit()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    _seed_default_model()
    yield


app = FastAPI(title="Sentinel AI", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(models.router)
app.include_router(attacks.router)
app.include_router(runs.router)
app.include_router(redteam.router)
app.include_router(scans.router)


@app.get("/api/health", tags=["health"])
def health():
    return {"status": "ok", "default_key_set": bool(settings.groq_api_key)}
