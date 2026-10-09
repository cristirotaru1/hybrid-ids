from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ServiceState(str, Enum):
    OK = "ok"
    CREATED = "created"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    BAD_REQUEST = "bad_request"
    AGENT_ERROR = "agent_error"
    RELOAD_FAILED = "reload_failed"


@dataclass(frozen=True)
class ServiceResult:
    state: ServiceState
    payload: dict = field(default_factory=dict)


@dataclass
class RuleHeader:
    action: str
    protocol: str
    src_ip: str
    src_port: str
    direction: str
    dst_ip: str
    dst_port: str

    @property
    def src(self) -> str:
        return f"{self.src_ip}:{self.src_port}"

    @property
    def dst(self) -> str:
        return f"{self.dst_ip}:{self.dst_port}"


@dataclass
class RuleSummary:
    sid: Optional[int]
    rev: Optional[int]
    action: Optional[str]
    protocol: Optional[str]
    src: Optional[str]
    dst: Optional[str]
    src_ip: Optional[str]
    src_port: Optional[str]
    direction: Optional[str]
    dst_ip: Optional[str]
    dst_port: Optional[str]
    msg: Optional[str]
    classtype: Optional[str]


@dataclass
class RuleDetail:
    sid: Optional[int]
    rev: Optional[int]
    msg: Optional[str]
    classtype: Optional[str]
    raw: str
    line_number: Optional[int]
    header: Optional[RuleHeader]
    options: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    status: str = "parsed"
