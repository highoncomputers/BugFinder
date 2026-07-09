from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from bugfinder.web.auth import get_current_user

router = APIRouter()


class CommentCreate(BaseModel):
    content: str


class CommentResponse(BaseModel):
    id: str
    finding_id: str
    author: str
    content: str
    created_at: str = ""
    updated_at: str = ""


@router.get("/findings/{finding_id}/comments", response_model=list[CommentResponse])
async def list_comments(finding_id: str, user: str = Depends(get_current_user)):
    from bugfinder.database.session import async_session
    from bugfinder.database.models import Comment, User
    from sqlalchemy import select

    async with async_session() as session:
        stmt = (
            select(Comment, User)
            .join(User, Comment.author_id == User.id)
            .where(Comment.finding_id == finding_id)
            .order_by(Comment.created_at.asc())
        )
        result = await session.execute(stmt)
        rows = result.all()
        return [
            CommentResponse(
                id=c.id, finding_id=c.finding_id,
                author=u.username,
                content=c.content,
                created_at=c.created_at.isoformat() if c.created_at else "",
                updated_at=c.updated_at.isoformat() if c.updated_at else "",
            )
            for c, u in rows
        ]


@router.post("/findings/{finding_id}/comments", response_model=CommentResponse, status_code=201)
async def create_comment(finding_id: str, data: CommentCreate, user: str = Depends(get_current_user)):
    from bugfinder.database.session import async_session
    from bugfinder.database.models import Comment, User
    from sqlalchemy import select

    async with async_session() as session:
        user_obj = await session.execute(select(User).where(User.username == user))
        user_obj = user_obj.scalar_one_or_none()
        if not user_obj:
            user_obj = User(username=user, role="member")
            session.add(user_obj)
            await session.commit()

        comment = Comment(
            finding_id=finding_id,
            author_id=user_obj.id,
            content=data.content,
        )
        session.add(comment)
        await session.commit()

        return CommentResponse(
            id=comment.id, finding_id=comment.finding_id,
            author=user_obj.username,
            content=comment.content,
            created_at=comment.created_at.isoformat() if comment.created_at else "",
            updated_at=comment.updated_at.isoformat() if comment.updated_at else "",
        )


@router.delete("/findings/{finding_id}/comments/{comment_id}")
async def delete_comment(finding_id: str, comment_id: str, user: str = Depends(get_current_user)):
    from bugfinder.database.session import async_session
    from bugfinder.database.models import Comment

    async with async_session() as session:
        comment = await session.get(Comment, comment_id)
        if not comment:
            raise HTTPException(status_code=404, detail="Comment not found")
        await session.delete(comment)
        await session.commit()
        return {"success": True}
