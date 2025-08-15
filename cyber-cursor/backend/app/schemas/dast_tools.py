from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


# -------- Dashboard --------

class DashboardTask(BaseModel):
    id: str
    name: str
    progress: int = Field(ge=0, le=100)
    status: str
    updated_at: str


class DashboardActivityResponse(BaseModel):
    active_tasks: List[DashboardTask]
    completed_tasks: List[DashboardTask]


class IssueSummaryResponse(BaseModel):
    high: int
    medium: int
    low: int


class DashboardEvent(BaseModel):
    id: str
    type: str
    message: str
    timestamp: str


class DashboardEventsResponse(BaseModel):
    events: List[DashboardEvent]


# -------- Target --------

class AddTargetRequest(BaseModel):
    url: Optional[str] = None
    label: Optional[str] = None
    type: Optional[str] = Field(default="path")
    parent_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class TargetNode(BaseModel):
    id: str
    parent_id: Optional[str] = None
    type: str
    label: str
    in_scope: bool
    metadata: Optional[Dict[str, Any]] = None


class TargetMapResponse(BaseModel):
    nodes: List[TargetNode]


# -------- Proxy --------

class ProxyEntry(BaseModel):
    id: str
    method: Optional[str] = None
    url: str
    status: Optional[int] = None
    size: Optional[int] = None
    time: Optional[str] = None


class ProxyHistoryResponse(BaseModel):
    entries: List[ProxyEntry]


class ProxyEntryDetail(BaseModel):
    id: str
    method: Optional[str] = None
    url: str
    status: Optional[int] = None
    size: Optional[int] = None
    time: Optional[str] = None
    request: Optional[Dict[str, Any]] = None
    response: Optional[Dict[str, Any]] = None
    created_at: Optional[str] = None


# -------- Repeater --------

class RepeaterSendRequest(BaseModel):
    method: str = Field(default="GET")
    url: str
    headers: Optional[Dict[str, Any]] = None
    body: Optional[str] = None


class RepeaterResponseBody(BaseModel):
    status: int
    headers: Dict[str, Any]
    body: Any
    size: int
    time_ms: int


class RepeaterSendResponse(BaseModel):
    status: str
    response: RepeaterResponseBody


class RepeaterHistoryItem(BaseModel):
    id: str
    method: str
    url: str
    status: Optional[int] = None
    created_at: Optional[str] = None


class RepeaterHistoryResponse(BaseModel):
    sessions: List[RepeaterHistoryItem]


# -------- Logger --------

class LoggerEntry(BaseModel):
    id: str
    method: Optional[str] = None
    url: str
    status: Optional[int] = None


class LoggerEntriesResponse(BaseModel):
    entries: List[LoggerEntry]


class LoggerEntryDetail(BaseModel):
    id: str
    method: Optional[str] = None
    url: str
    status: Optional[int] = None
    details: Optional[Dict[str, Any]] = None
    created_at: Optional[str] = None


# -------- Sequencer --------

class SequencerStartResponse(BaseModel):
    sequence_id: str
    status: str


class SequencerResultsResponse(BaseModel):
    sequence_id: str
    entropy: float
    histogram: Dict[str, int]
    recommendations: List[str]


# -------- Decoder --------

class DecoderTransformRequest(BaseModel):
    mode: str
    text: str


class DecoderTransformResponse(BaseModel):
    output: str


# -------- Comparer --------

class ComparerRequest(BaseModel):
    left: str
    right: str
    mode: Optional[str] = Field(default="words")


class ComparerResponse(BaseModel):
    mode: str
    differences: List[Dict[str, Any]]


# -------- Extender --------

class ExtensionInfo(BaseModel):
    name: str
    author: str
    status: str


class ExtenderListResponse(BaseModel):
    installed: List[ExtensionInfo]


class ExtenderInstallRequest(BaseModel):
    name: str


class ExtenderActionResponse(BaseModel):
    status: str
    extension: Optional[str] = None
    extension_id: Optional[str] = None


# -------- Scanner --------

class ScannerStartResponse(BaseModel):
    scan_id: str
    status: str


class ScannerStatusResponse(BaseModel):
    scan_id: str
    status: str
    progress: int


class ScannerIssue(BaseModel):
    severity: str
    description: str
    confidence: str


class ScannerIssuesResponse(BaseModel):
    issues: List[ScannerIssue]


# -------- Settings --------

class SettingsResponse(BaseModel):
    project: Dict[str, Any]
    user: Dict[str, Any]


class UpdateSettingsResponse(BaseModel):
    status: str
    project_id: str
    settings: Dict[str, Any]


# -------- Membership --------

class MemberItem(BaseModel):
    user_id: int
    role: str
    created_at: Optional[str] = None


class MembersResponse(BaseModel):
    members: List[MemberItem]


class AddMemberRequest(BaseModel):
    user_id: int
    role: str = Field(default="member")


class MemberActionResponse(BaseModel):
    status: str

