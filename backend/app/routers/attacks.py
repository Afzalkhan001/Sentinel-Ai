from fastapi import APIRouter, HTTPException

from ..attacks.loader import get_attack, load_attacks
from ..schemas import AttackOut

router = APIRouter(prefix="/api/attacks", tags=["attacks"])


@router.get("", response_model=list[AttackOut])
def list_attacks(category: str | None = None):
    attacks = load_attacks()
    if category:
        attacks = [a for a in attacks if a.category == category]
    return attacks


@router.get("/{attack_id}", response_model=AttackOut)
def get_one(attack_id: str):
    attack = get_attack(attack_id)
    if not attack:
        raise HTTPException(404, "Attack not found")
    return attack
