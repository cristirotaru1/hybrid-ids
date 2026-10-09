"""Define the normalized Snort alert shared by all layers."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class AlertEvent:
    sid: int
    gid: int
    priority: int
    msg: str
    proto: str
    src_addr: str
    src_port: int | None
    dst_addr: str
    dst_port: int | None
    action: str
    iface: str
    ts: datetime

    @property
    def is_high_priority(self) -> bool:
        return self.priority == 1
