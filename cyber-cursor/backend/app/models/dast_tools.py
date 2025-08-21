from sqlalchemy import Column, UUID, String, Integer, DateTime, JSON, ForeignKey, Text, Boolean, Index, delete, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.sql import func
from typing import List, Optional
import uuid
from datetime import datetime, timedelta
import secrets
import re
from sqlalchemy.exc import IntegrityError

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
    __table_args__ = (
        Index("ix_dast_proxy_entries_project_created", "project_id", "created_at"),
        Index("ix_dast_proxy_entries_method", "method"),
        Index("ix_dast_proxy_entries_status", "status"),
    )

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


class DASTCAConfig(Base):
    __tablename__ = "dast_ca_configs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)
    # PEMs stored securely (consider external secrets manager in prod)
    ca_cert_pem = Column(Text, nullable=True)
    ca_key_pem = Column(Text, nullable=True)
    enabled = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now())

    @classmethod
    async def get_by_project(cls, db: AsyncSession, project_id: str) -> Optional["DASTCAConfig"]:
        row = await db.execute(select(cls).where(cls.project_id == project_id))
        return row.scalars().first()

    @classmethod
    async def upsert(cls, db: AsyncSession, *, project_id: str, ca_cert_pem: Optional[str], ca_key_pem: Optional[str], enabled: bool) -> "DASTCAConfig":
        row = await cls.get_by_project(db, project_id)
        if row:
            row.ca_cert_pem = ca_cert_pem
            row.ca_key_pem = ca_key_pem
            row.enabled = enabled
        else:
            row = cls(project_id=project_id, ca_cert_pem=ca_cert_pem, ca_key_pem=ca_key_pem, enabled=enabled)
            db.add(row)
        await db.commit()
        await db.refresh(row)
        return row


class DASTLogEntry(Base):
    __tablename__ = "dast_log_entries"
    __table_args__ = (
        Index("ix_dast_log_entries_project_created", "project_id", "created_at"),
        Index("ix_dast_log_entries_method", "method"),
        Index("ix_dast_log_entries_status", "status"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)

    method = Column(String(10), nullable=True)
    url = Column(Text, nullable=False)
    status = Column(Integer, nullable=True)
    details = Column(JSON, nullable=True)
    bookmarked = Column(Boolean, default=False)
    note = Column(Text, nullable=True)

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

    @classmethod
    async def set_bookmarked(cls, db: AsyncSession, *, entry_id: str, bookmarked: bool) -> Optional["DASTLogEntry"]:
        row = await cls.get_by_id(db, entry_id)
        if not row:
            return None
        row.bookmarked = bool(bookmarked)
        await db.commit()
        await db.refresh(row)
        return row

    @classmethod
    async def set_note(cls, db: AsyncSession, *, entry_id: str, note: Optional[str]) -> Optional["DASTLogEntry"]:
        row = await cls.get_by_id(db, entry_id)
        if not row:
            return None
        row.note = note
        await db.commit()
        await db.refresh(row)
        return row


class DASTTargetNode(Base):
    __tablename__ = "dast_target_nodes"
    __table_args__ = (
        Index("ix_dast_target_nodes_project", "project_id"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)

    parent_id = Column(UUID(as_uuid=True), nullable=True)
    node_type = Column(String(20), nullable=False, default="path")  # domain|path|file
    label = Column(Text, nullable=False)
    # 'metadata' is reserved in SQLAlchemy Declarative; map to column name 'metadata'
    node_metadata = Column("metadata", JSON, nullable=True)

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
            node_metadata=metadata,
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

    @classmethod
    async def ensure_url_nodes(cls, db: AsyncSession, *, project_id: str, url: str) -> None:
        """Create domain/path nodes for a URL if missing."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.hostname or ""
            if not host:
                return
            # Create domain node
            result = await db.execute(select(cls).where(cls.project_id == project_id, cls.label == host, cls.node_type == "domain"))
            domain_node = result.scalar_one_or_none()
            if domain_node is None:
                domain_node = cls(project_id=project_id, label=host, node_type="domain", in_scope=True)
                db.add(domain_node)
                await db.flush()
            parent_id = domain_node.id
            # Create path segments
            path = (parsed.path or "/").strip()
            if not path or path == "/":
                await db.commit()
                return
            segments = [seg for seg in path.split("/") if seg]
            current_parent = parent_id
            built = ""
            for seg in segments:
                built = f"{built}/{seg}"
                result = await db.execute(select(cls).where(cls.project_id == project_id, cls.label == built, cls.node_type == "path"))
                node = result.scalar_one_or_none()
                if node is None:
                    node = cls(project_id=project_id, label=built, node_type="path", parent_id=current_parent, in_scope=True)
                    db.add(node)
                    await db.flush()
                current_parent = node.id
            await db.commit()
        except Exception:
            # best-effort only
            try:
                await db.rollback()
            except Exception:
                pass


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


class DASTIntercept(Base):
    __tablename__ = "dast_intercepts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)
    request = Column(JSON, nullable=False)
    status = Column(String(20), default="pending")  # pending, forwarded, dropped
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    @classmethod
    async def enqueue(cls, db: AsyncSession, *, project_id: str, request: dict) -> "DASTIntercept":
        row = cls(project_id=project_id, request=request, status="pending")
        db.add(row)
        await db.commit()
        await db.refresh(row)
        return row

    @classmethod
    async def list_pending(cls, db: AsyncSession, project_id: str, limit: int = 100) -> list["DASTIntercept"]:
        result = await db.execute(select(cls).where(cls.project_id == project_id, cls.status == "pending").order_by(cls.created_at.asc()).limit(limit))
        return result.scalars().all()

    @classmethod
    async def get_by_id(cls, db: AsyncSession, intercept_id: str) -> Optional["DASTIntercept"]:
        result = await db.execute(select(cls).where(cls.id == intercept_id))
        return result.scalar_one_or_none()


class DASTProxySettings(Base):
    __tablename__ = "dast_proxy_settings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False, unique=True)
    settings = Column(JSON, nullable=True)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    @classmethod
    async def get_by_project(cls, db: AsyncSession, project_id: str) -> Optional["DASTProxySettings"]:
        result = await db.execute(select(cls).where(cls.project_id == project_id))
        return result.scalar_one_or_none()

    @classmethod
    async def set_for_project(cls, db: AsyncSession, *, project_id: str, settings: dict) -> "DASTProxySettings":
        row = await cls.get_by_project(db, project_id)
        if row is None:
            row = cls(project_id=project_id, settings=settings)
            db.add(row)
        else:
            row.settings = settings
        await db.commit()
        await db.refresh(row)
        return row


class DASTProxyCA(Base):
    __tablename__ = "dast_proxy_ca"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False, unique=True)
    enabled = Column(Boolean, default=False)
    ca_cert_pem = Column(Text, nullable=True)
    ca_key_pem = Column(Text, nullable=True)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    @classmethod
    async def get_by_project(cls, db: AsyncSession, project_id: str) -> Optional["DASTProxyCA"]:
        result = await db.execute(select(cls).where(cls.project_id == project_id))
        return result.scalar_one_or_none()

    @classmethod
    async def upsert(
        cls,
        db: AsyncSession,
        *,
        project_id: str,
        enabled: Optional[bool] = None,
        ca_cert_pem: Optional[str] = None,
        ca_key_pem: Optional[str] = None,
    ) -> "DASTProxyCA":
        row = await cls.get_by_project(db, project_id)
        if row is None:
            row = cls(project_id=project_id)
            db.add(row)
        if enabled is not None:
            row.enabled = enabled
        if ca_cert_pem is not None:
            row.ca_cert_pem = ca_cert_pem
        if ca_key_pem is not None:
            row.ca_key_pem = ca_key_pem
        await db.commit()
        await db.refresh(row)
        return row

# Backwards-compatible alias for code importing DASTCAConfig
DASTCAConfig = DASTProxyCA


class DASTWSFrame(Base):
    __tablename__ = "dast_ws_frames"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)
    direction = Column(String(8), nullable=False)
    opcode = Column(Integer, nullable=False)
    text = Column(Text, nullable=True)
    payload_base64 = Column(Text, nullable=True)
    entry_id = Column(UUID(as_uuid=True), ForeignKey("dast_proxy_entries.id"), nullable=True)
    pinned = Column(Boolean, default=False)
    note = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    @classmethod
    async def create(
        cls,
        db: AsyncSession,
        *,
        project_id: str,
        direction: str,
        opcode: int,
        text: Optional[str] = None,
        payload_base64: Optional[str] = None,
        entry_id: Optional[str] = None,
    ) -> "DASTWSFrame":
        row = cls(project_id=project_id, direction=direction, opcode=opcode, text=text, payload_base64=payload_base64, entry_id=entry_id)
        db.add(row)
        await db.commit()
        await db.refresh(row)
        return row

    @classmethod
    async def list_by_project(cls, db: AsyncSession, project_id: str, limit: int = 200) -> List["DASTWSFrame"]:
        result = await db.execute(select(cls).where(cls.project_id == project_id).order_by(cls.created_at.desc()).limit(limit))
        return result.scalars().all()

    @classmethod
    async def get_by_id(cls, db: AsyncSession, frame_id: str) -> Optional["DASTWSFrame"]:
        result = await db.execute(select(cls).where(cls.id == frame_id))
        return result.scalar_one_or_none()

    @classmethod
    async def set_pinned(cls, db: AsyncSession, *, frame_id: str, pinned: bool) -> Optional["DASTWSFrame"]:
        row = await cls.get_by_id(db, frame_id)
        if not row:
            return None
        row.pinned = bool(pinned)
        await db.commit()
        await db.refresh(row)
        return row


class DASTAuditEvent(Base):
    __tablename__ = "dast_audit_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)
    user_id = Column(Integer, nullable=True)
    action = Column(String(100), nullable=False)
    object_type = Column(String(50), nullable=True)
    object_id = Column(String(100), nullable=True)
    audit_metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    @classmethod
    async def log(
        cls,
        db: AsyncSession,
        *,
        project_id: str,
        user_id: Integer | None,
        action: str,
        object_type: str | None = None,
        object_id: str | None = None,
        metadata: dict | None = None,
    ) -> "DASTAuditEvent":
        row = cls(project_id=project_id, user_id=user_id, action=action, object_type=object_type, object_id=object_id, audit_metadata=metadata)
        db.add(row)
        await db.commit()
        await db.refresh(row)
        return row


class DASTLock(Base):
    __tablename__ = "dast_locks"
    __table_args__ = (
        Index("ix_dast_locks_resource", "resource_type", "resource_id"),
        Index("ix_dast_locks_owner", "owner_id"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)
    resource_type = Column(String(50), nullable=False)  # 'intercept', 'repeater_tab', etc.
    resource_id = Column(String(128), nullable=False)
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, server_default=func.now())

    @classmethod
    async def acquire(cls, db: AsyncSession, *, project_id: str, resource_type: str, resource_id: str, owner_id: str, ttl_seconds: int = 300) -> "DASTLock | None":
        # clear expired locks first
        await db.execute(delete(cls).where(cls.expires_at < func.now()))
        
        # try to acquire
        expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)
        lock = cls(project_id=project_id, resource_type=resource_type, resource_id=resource_id, owner_id=owner_id, expires_at=expires_at)
        try:
            db.add(lock)
            await db.commit()
            await db.refresh(lock)
            return lock
        except IntegrityError:
            await db.rollback()
            return None

    @classmethod
    async def release(cls, db: AsyncSession, *, project_id: str, resource_type: str, resource_id: str, owner_id: str) -> bool:
        result = await db.execute(
            delete(cls).where(
                cls.project_id == project_id,
                cls.resource_type == resource_type,
                cls.resource_id == resource_id,
                cls.owner_id == owner_id
            )
        )
        await db.commit()
        return result.rowcount > 0


class DASTIngestToken(Base):
    __tablename__ = "dast_ingest_tokens"
    __table_args__ = (
        Index("ix_dast_ingest_tokens_project", "project_id"),
        Index("ix_dast_ingest_tokens_token", "token"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)
    token = Column(String(128), nullable=False, unique=True)
    name = Column(String(100), nullable=False)  # e.g., "Proxy Engine 1", "Crawler"
    expires_at = Column(DateTime, nullable=True)  # null = never expires
    created_at = Column(DateTime, server_default=func.now())
    last_used_at = Column(DateTime, nullable=True)

    @classmethod
    async def create_for_project(cls, db: AsyncSession, *, project_id: str, name: str, expires_in_days: Optional[int] = None) -> "DASTIngestToken":
        token = secrets.token_urlsafe(32)
        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
        
        ingest_token = cls(project_id=project_id, token=token, name=name, expires_at=expires_at)
        db.add(ingest_token)
        await db.commit()
        await db.refresh(ingest_token)
        return ingest_token

    @classmethod
    async def validate(cls, db: AsyncSession, *, token: str, project_id: str) -> "DASTIngestToken | None":
        result = await db.execute(
            select(cls).where(
                cls.token == token,
                cls.project_id == project_id,
                or_(cls.expires_at.is_(None), cls.expires_at > func.now())
            )
        )
        ingest_token = result.scalars().first()
        if ingest_token:
            # update last used
            ingest_token.last_used_at = datetime.utcnow()
            await db.commit()
        return ingest_token


class DASTMatchReplaceRule(Base):
    __tablename__ = "dast_match_replace_rules"
    __table_args__ = (
        Index("ix_dast_match_replace_rules_project", "project_id"),
        Index("ix_dast_match_replace_rules_order", "project_id", "order_index"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    enabled = Column(Boolean, default=True)
    order_index = Column(Integer, default=0)
    
    # Match criteria
    match_type = Column(String(20), nullable=False)  # 'url', 'header', 'body', 'response'
    match_pattern = Column(String(500), nullable=False)  # regex pattern
    match_case_sensitive = Column(Boolean, default=False)
    
    # Replace action
    replace_type = Column(String(20), nullable=False)  # 'header', 'body', 'url'
    replace_pattern = Column(String(500), nullable=False)  # regex replacement
    replace_value = Column(Text, nullable=True)  # static value if replace_pattern is empty
    
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    @classmethod
    async def get_active_rules(cls, db: AsyncSession, *, project_id: str) -> List["DASTMatchReplaceRule"]:
        result = await db.execute(
            select(cls).where(
                cls.project_id == project_id,
                cls.enabled == True
            ).order_by(cls.order_index)
        )
        return result.scalars().all()

    def apply_to_request(self, request: dict) -> dict:
        """Apply this rule to a request, returning modified request."""
        if not self.enabled:
            return request
        
        modified = request.copy()
        
        if self.match_type == 'url':
            if re.search(self.match_pattern, request.get('url', ''), flags=0 if self.match_case_sensitive else re.IGNORECASE):
                if self.replace_type == 'url':
                    if self.replace_pattern:
                        modified['url'] = re.sub(self.replace_pattern, self.replace_value or '', request.get('url', ''))
                    else:
                        modified['url'] = self.replace_value
        
        elif self.match_type == 'header':
            headers = dict(request.get('headers', {}))
            for header_name, header_value in headers.items():
                if re.search(self.match_pattern, f"{header_name}: {header_value}", flags=0 if self.match_case_sensitive else re.IGNORECASE):
                    if self.replace_type == 'header':
                        if self.replace_pattern:
                            new_value = re.sub(self.replace_pattern, self.replace_value or '', header_value)
                        else:
                            new_value = self.replace_value
                        if new_value is not None:
                            headers[header_name] = new_value
            modified['headers'] = headers
        
        elif self.match_type == 'body':
            body = request.get('body', '')
            if re.search(self.match_pattern, body, flags=0 if self.match_case_sensitive else re.IGNORECASE):
                if self.replace_type == 'body':
                    if self.replace_pattern:
                        modified['body'] = re.sub(self.replace_pattern, self.replace_value or '', body)
                    else:
                        modified['body'] = self.replace_value
        
        return modified

    def apply_to_response(self, response: dict) -> dict:
        """Apply this rule to a response, returning modified response."""
        if not self.enabled or self.match_type != 'response':
            return response
        
        modified = response.copy()
        
        if re.search(self.match_pattern, response.get('body', ''), flags=0 if self.match_case_sensitive else re.IGNORECASE):
            if self.replace_type == 'body':
                if self.replace_pattern:
                    modified['body'] = re.sub(self.replace_pattern, self.replace_value or '', response.get('body', ''))
                else:
                    modified['body'] = self.replace_value
        
        return modified


class DASTProxyCorrelation(Base):
    __tablename__ = "dast_proxy_correlations"
    __table_args__ = (
        Index("ix_dast_proxy_corr_proj_corr", "project_id", "correlation_id"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)
    correlation_id = Column(String(128), nullable=False)
    entry_id = Column(UUID(as_uuid=True), ForeignKey("dast_proxy_entries.id"), nullable=False)
    created_at = Column(DateTime, server_default=func.now())

    @classmethod
    async def upsert(cls, db: AsyncSession, *, project_id: str, correlation_id: str, entry_id: str) -> "DASTProxyCorrelation":
        # simple insert; duplicates allowed newest wins for lookups
        row = cls(project_id=project_id, correlation_id=correlation_id, entry_id=entry_id)
        db.add(row)
        await db.commit()
        await db.refresh(row)
        return row

    @classmethod
    async def get_latest(cls, db: AsyncSession, *, project_id: str, correlation_id: str) -> "DASTProxyCorrelation | None":
        result = await db.execute(
            select(cls).where(cls.project_id == project_id, cls.correlation_id == correlation_id).order_by(cls.created_at.desc()).limit(1)
        )
        return result.scalars().first()

    @classmethod
    async def set_note(cls, db: AsyncSession, *, frame_id: str, note: Optional[str]) -> Optional["DASTWSFrame"]:
        row = await cls.get_by_id(db, frame_id)
        if not row:
            return None
        row.note = note
        await db.commit()
        await db.refresh(row)
        return row

