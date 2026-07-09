from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from bugfinder.web.auth import get_current_user

router = APIRouter()


@router.get("/tutorials")
async def list_tutorials():
    from bugfinder.learning.tutorials import list_tutorials as _list

    return _list()


@router.get("/tutorials/{tutorial_id}")
async def get_tutorial(tutorial_id: str):
    from bugfinder.learning.tutorials import get_tutorial

    t = get_tutorial(tutorial_id)
    if not t:
        raise HTTPException(status_code=404, detail="Tutorial not found")
    return {
        "id": t.id,
        "title": t.title,
        "description": t.description,
        "difficulty": t.difficulty,
        "category": t.category,
        "duration_minutes": t.duration_minutes,
        "steps": [
            {
                "title": s.title,
                "content": s.content,
                "code": s.code,
                "language": s.language,
                "expected": s.expected,
            }
            for s in t.steps
        ],
        "references": t.references,
    }
