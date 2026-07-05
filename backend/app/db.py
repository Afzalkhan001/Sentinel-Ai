from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import settings

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


def init_db() -> None:
    # Import models so they are registered on Base before create_all
    from . import models_db  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _ensure_columns()


# Columns added after the first release. SQLite create_all won't alter existing
# tables, so we add any missing ones here (idempotent).
_MIGRATIONS = [
    ("registered_models", "request_config", "JSON"),
    ("runs", "inconclusive_count", "INTEGER DEFAULT 0"),
]


def _ensure_columns() -> None:
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    with engine.begin() as conn:
        for table, column, coltype in _MIGRATIONS:
            if table not in existing_tables:
                continue
            cols = {c["name"] for c in inspector.get_columns(table)}
            if column not in cols:
                conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {column} {coltype}'))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
