"""In-memory API-key vault. Keys live in RAM only, never persisted to disk.

Keyed by RegisteredModel.id. Lost on server restart (user re-enters) — acceptable
for a local single-user MVP. SQLite only stores the last-4 for display.
"""
from threading import Lock

_vault: dict[str, str] = {}
_lock = Lock()


def set_key(model_id: str, api_key: str) -> None:
    with _lock:
        _vault[model_id] = api_key


def get_key(model_id: str) -> str | None:
    with _lock:
        return _vault.get(model_id)


def delete_key(model_id: str) -> None:
    with _lock:
        _vault.pop(model_id, None)


def last4(api_key: str | None) -> str | None:
    if not api_key:
        return None
    return api_key[-4:]
