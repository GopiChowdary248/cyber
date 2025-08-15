from sqlalchemy import Column, UUID, String, Integer, DateTime, JSON, ForeignKey, Text, Boolean
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.sql import func
from typing import List, Optional
import uuid

from app.core.database import Base


class DASTProjectMember(Base):
    __tablename__ = "dast_project_members"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)
    user_id = Column(Integer, nullable=False)
    role = Column(String(50), nullable=False, default="member")  # owner, analyst, viewer
    created_at = Column(DateTime, server_default=func.now())

    @classmethod
    async def is_member(cls, db: AsyncSession, project_id: str, user_id: int) -> bool:
        result = await db.execute(select(cls).where(cls.project_id == project_id, cls.user_id == user_id))
        return result.scalar_one_or_none() is not None

    @classmethod
    async def add_member(cls, db: AsyncSession, *, project_id: str, user_id: int, role: str = "member") -> "DASTProjectMember":
        row = cls(project_id=project_id, user_id=user_id, role=role)
        db.add(row)
        await db.commit()
        await db.refresh(row)
        return row


class DASTProxyEntry(Base):
    __tablename__ = "dast_proxy_entries"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)

    method = Column(String(10), nullable=False)
    url = Column(Text, nullable=False)
    status = Column(Integer, nullable=True)
    size = Column(Integer, nullable=True)
    time = Column(DateTime, nullable=True)

    request = Column(JSON, nullable=True)
    response = Column(JSON, nullable=True)

    created_at = Column(DateTime, server_default=func.now())

    @classmethod
    async def create(
        cls,
        db: AsyncSession,
        *,
        project_id: str,
        method: str,
        url: str,
        status: Optional[int] = None,
        size: Optional[int] = None,
        time: Optional[str] = None,
        request: Optional[dict] = None,
        response: Optional[dict] = None,
    ) -> "DASTProxyEntry":
        entry = cls(
            project_id=project_id,
            method=method,
            url=url,
            status=status,
            size=size,
            time=time,
            request=request,
            response=response,
        )
        db.add(entry)
        await db.commit()
        await db.refresh(entry)
        return entry

    @classmethod
    async def get_latest_by_project(
        cls, db: AsyncSession, project_id: str, limit: int = 200
    ) -> List["DASTProxyEntry"]:
        result = await db.execute(
            select(cls)
            .where(cls.project_id == project_id)
            .order_by(cls.created_at.desc())
            .limit(limit)
        )
        return result.scalars().all()

    @classmethod
    async def get_by_id(cls, db: AsyncSession, entry_id: str) -> Optional["DASTProxyEntry"]:
        result = await db.execute(select(cls).where(cls.id == entry_id))
        return result.scalar_one_or_none()


class DASTLogEntry(Base):
    __tablename__ = "dast_log_entries"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)

    method = Column(String(10), nullable=True)
    url = Column(Text, nullable=False)
    status = Column(Integer, nullable=True)
    details = Column(JSON, nullable=True)

    created_at = Column(DateTime, server_default=func.now())

    @classmethod
    async def create(
        cls,
        db: AsyncSession,
        *,
        project_id: str,
        method: Optional[str],
        url: str,
        status: Optional[int],
        details: Optional[dict] = None,
    ) -> "DASTLogEntry":
        entry = cls(
            project_id=project_id,
            method=method,
            url=url,
            status=status,
            details=details,
        )
        db.add(entry)
        await db.commit()
        await db.refresh(entry)
        return entry

    @classmethod
    async def get_latest_by_project(
        cls, db: AsyncSession, project_id: str, limit: int = 500, q: Optional[str] = None
    ) -> List["DASTLogEntry"]:
        query = select(cls).where(cls.project_id == project_id)
        if q:
            # Simple contains filter on URL
            query = query.where(cls.url.ilike(f"%{q}%"))
        query = query.order_by(cls.created_at.desc()).limit(limit)
        result = await db.execute(query)
        return result.scalars().all()

    @classmethod
    async def get_by_id(cls, db: AsyncSession, entry_id: str) -> Optional["DASTLogEntry"]:
        result = await db.execute(select(cls).where(cls.id == entry_id))
        return result.scalar_one_or_none()


class DASTTargetNode(Base):
    __tablename__ = "dast_target_nodes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)

    parent_id = Column(UUID(as_uuid=True), nullable=True)
    node_type = Column(String(20), nullable=False, default="path")  # domain|path|file
    label = Column(Text, nullable=False)
    metadata = Column(JSON, nullable=True)

    discovered = Column(Boolean, default=True)
    in_scope = Column(Boolean, default=True)
    created_at = Column(DateTime, server_default=func.now())

    @classmethod
    async def add_node(
        cls, db: AsyncSession, *, project_id: str, label: str, node_type: str = "path", parent_id: Optional[str] = None, metadata: Optional[dict] = None, in_scope: bool = True
    ) -> "DASTTargetNode":
        node = cls(
            project_id=project_id,
            label=label,
            node_type=node_type,
            parent_id=parent_id,
            metadata=metadata,
            in_scope=in_scope,
        )
        db.add(node)
        await db.commit()
        await db.refresh(node)
        return node

    @classmethod
    async def list_by_project(cls, db: AsyncSession, project_id: str) -> List["DASTTargetNode"]:
        result = await db.execute(select(cls).where(cls.project_id == project_id))
        return result.scalars().all()


class DASTRepeaterEntry(Base):
    __tablename__ = "dast_repeater_entries"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)

    method = Column(String(10), nullable=False, default="GET")
    url = Column(Text, nullable=False)
    headers = Column(JSON, nullable=True)
    body = Column(Text, nullable=True)

    response = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    @classmethod
    async def create(
        cls, db: AsyncSession, *, project_id: str, method: str, url: str, headers: Optional[dict], body: Optional[str], response: Optional[dict]
    ) -> "DASTRepeaterEntry":
        row = cls(project_id=project_id, method=method, url=url, headers=headers, body=body, response=response)
        db.add(row)
        await db.commit()
        await db.refresh(row)
        return row

    @classmethod
    async def list_by_project(cls, db: AsyncSession, project_id: str, limit: int = 100) -> List["DASTRepeaterEntry"]:
        result = await db.execute(
            select(cls).where(cls.project_id == project_id).order_by(cls.created_at.desc()).limit(limit)
        )
        return result.scalars().all()


