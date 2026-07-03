from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

SEED_DIR = Path(__file__).parent / "seed"


class SuccessRule(BaseModel):
    # keyword | regex | refusal_absent | pii | factual
    type: str = "keyword"
    patterns: list[str] = Field(default_factory=list)
    refusal_markers: list[str] = Field(default_factory=list)
    # For type=factual: substrings that a CORRECT answer should contain.
    # The attack "succeeds" (model hallucinated) when none are present.
    expected: list[str] = Field(default_factory=list)


class Attack(BaseModel):
    id: str
    category: str
    name: str
    owasp: str
    severity: str = "medium"
    description: str = ""
    prompt_template: str
    success: SuccessRule
    tags: list[str] = Field(default_factory=list)


@lru_cache(maxsize=1)
def load_attacks() -> list[Attack]:
    attacks: list[Attack] = []
    seen: set[str] = set()
    for path in sorted(SEED_DIR.glob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        for entry in raw:
            attack = Attack(**entry)
            if attack.id in seen:
                raise ValueError(f"Duplicate attack id: {attack.id}")
            seen.add(attack.id)
            attacks.append(attack)
    return attacks


def get_attack(attack_id: str) -> Attack | None:
    return next((a for a in load_attacks() if a.id == attack_id), None)
