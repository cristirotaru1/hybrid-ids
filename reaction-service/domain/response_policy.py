"""Filter alerts that merit operator notification."""

from domain.alert_event import AlertEvent


class ResponsePolicy:
    def __init__(
        self,
        allowlist: set[tuple[str, str]] | None = None,
    ):
        self._allowlist: set[tuple[str, str]] = allowlist or set()

    def evaluate(self, alert: AlertEvent) -> AlertEvent | None:
        """Return the alert only when it passes the notification policy."""
        if not alert.is_high_priority:
            return None

        pair = (alert.src_addr, alert.dst_addr)

        if pair in self._allowlist:
            return None

        return alert
