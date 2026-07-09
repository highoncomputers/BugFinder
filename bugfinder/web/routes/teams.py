from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from bugfinder.web.auth import get_current_user

router = APIRouter()


class TeamCreate(BaseModel):
    name: str
    description: str = ""


class TeamResponse(BaseModel):
    id: str
    name: str
    description: str
    member_count: int = 0
    created_at: str = ""


class MemberResponse(BaseModel):
    id: str
    username: str
    role: str
    joined_at: str = ""


@router.get("", response_model=list[TeamResponse])
async def list_teams(user: str = Depends(get_current_user)):
    from bugfinder.database.session import async_session
    from bugfinder.database.models import Team, TeamMembership
    from sqlalchemy import select, func

    async with async_session() as session:
        stmt = select(Team).order_by(Team.name)
        result = await session.execute(stmt)
        teams = result.scalars().all()

        team_list = []
        for t in teams:
            count_stmt = select(func.count(TeamMembership.id)).where(TeamMembership.team_id == t.id)
            count_result = await session.execute(count_stmt)
            count = count_result.scalar() or 0
            team_list.append(TeamResponse(
                id=t.id, name=t.name, description=t.description or "",
                member_count=count,
                created_at=t.created_at.isoformat() if t.created_at else "",
            ))
        return team_list


@router.post("", response_model=TeamResponse, status_code=201)
async def create_team(data: TeamCreate, user: str = Depends(get_current_user)):
    from bugfinder.database.session import async_session
    from bugfinder.database.models import Team

    async with async_session() as session:
        team = Team(name=data.name, description=data.description, created_by=user)
        session.add(team)
        await session.commit()
        return TeamResponse(
            id=team.id, name=team.name, description=team.description or "",
            created_at=team.created_at.isoformat() if team.created_at else "",
        )


@router.get("/{team_id}", response_model=TeamResponse)
async def get_team(team_id: str, user: str = Depends(get_current_user)):
    from bugfinder.database.session import async_session
    from bugfinder.database.models import Team, TeamMembership
    from sqlalchemy import select, func

    async with async_session() as session:
        team = await session.get(Team, team_id)
        if not team:
            raise HTTPException(status_code=404, detail="Team not found")
        count_stmt = select(func.count(TeamMembership.id)).where(TeamMembership.team_id == team.id)
        count_result = await session.execute(count_stmt)
        count = count_result.scalar() or 0
        return TeamResponse(
            id=team.id, name=team.name, description=team.description or "",
            member_count=count,
            created_at=team.created_at.isoformat() if team.created_at else "",
        )


@router.delete("/{team_id}")
async def delete_team(team_id: str, user: str = Depends(get_current_user)):
    from bugfinder.database.session import async_session
    from bugfinder.database.models import Team

    async with async_session() as session:
        team = await session.get(Team, team_id)
        if not team:
            raise HTTPException(status_code=404, detail="Team not found")
        await session.delete(team)
        await session.commit()
        return {"success": True}


@router.get("/{team_id}/members", response_model=list[MemberResponse])
async def list_members(team_id: str, user: str = Depends(get_current_user)):
    from bugfinder.database.session import async_session
    from bugfinder.database.models import TeamMembership, User
    from sqlalchemy import select

    async with async_session() as session:
        stmt = (
            select(TeamMembership, User)
            .join(User, TeamMembership.user_id == User.id)
            .where(TeamMembership.team_id == team_id)
        )
        result = await session.execute(stmt)
        rows = result.all()
        return [
            MemberResponse(
                id=u.id, username=u.username, role=m.role,
                joined_at=m.joined_at.isoformat() if m.joined_at else "",
            )
            for m, u in rows
        ]


@router.post("/{team_id}/members")
async def add_member(team_id: str, data: dict, user: str = Depends(get_current_user)):
    from bugfinder.database.session import async_session
    from bugfinder.database.models import TeamMembership

    username = data.get("username", "")
    role = data.get("role", "member")

    async with async_session() as session:
        from bugfinder.database.models import User
        from sqlalchemy import select

        user_obj = await session.execute(select(User).where(User.username == username))
        user_obj = user_obj.scalar_one_or_none()
        if not user_obj:
            raise HTTPException(status_code=404, detail="User not found")

        existing = await session.execute(
            select(TeamMembership).where(
                TeamMembership.team_id == team_id,
                TeamMembership.user_id == user_obj.id,
            )
        )
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="User already in team")

        membership = TeamMembership(team_id=team_id, user_id=user_obj.id, role=role)
        session.add(membership)
        await session.commit()
        return {"success": True}


@router.delete("/{team_id}/members/{user_id}")
async def remove_member(team_id: str, user_id: str, user: str = Depends(get_current_user)):
    from bugfinder.database.session import async_session
    from bugfinder.database.models import TeamMembership
    from sqlalchemy import select

    async with async_session() as session:
        stmt = select(TeamMembership).where(
            TeamMembership.team_id == team_id,
            TeamMembership.user_id == user_id,
        )
        result = await session.execute(stmt)
        membership = result.scalar_one_or_none()
        if not membership:
            raise HTTPException(status_code=404, detail="Membership not found")
        await session.delete(membership)
        await session.commit()
        return {"success": True}
