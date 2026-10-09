"""Convert Snort JSON alerts to domain events."""

import json
import logging
from datetime import datetime, timezone
from domain.alert_event import AlertEvent

logger = logging.getLogger(__name__)


class AlertNormalizer:
    def parse(self, raw_line: str) -> AlertEvent | None:
        """Return a normalized alert, or ``None`` for invalid input."""
        if not raw_line:
            return None

        try:
            data = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            logger.warning("JSON parse error: %s | line: %.120s", exc, raw_line)
            return None

        try:
            # Snort writes `seconds` as a Unix timestamp.
            ts = datetime.fromtimestamp(float(data["seconds"]), tz=timezone.utc)

            return AlertEvent(
                sid=int(data["sid"]),
                gid=int(data.get("gid", 1)),
                priority=int(data["priority"]),
                msg=str(data.get("msg", "")),
                proto=str(data.get("proto", "")),
                src_addr=str(data["src_addr"]),
                src_port=_int_or_none(data.get("src_port")),
                dst_addr=str(data["dst_addr"]),
                dst_port=_int_or_none(data.get("dst_port")),
                action=str(data.get("action", "")),
                iface=str(data.get("iface", "")),
                ts=ts,
            )
        except (KeyError, ValueError, TypeError) as exc:
            logger.warning("Alert normalization error: %s | data: %s", exc, data)
            return None


def _int_or_none(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
