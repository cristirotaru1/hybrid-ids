import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from application.reaction_service import ReactionService
from domain.alert_event import AlertEvent
from reaction_common import ReactionStore


class _Tailer:
    def tail(self):
        yield "alert"


class _Normalizer:
    def __init__(self, alert):
        self.alert = alert

    def parse(self, _raw):
        return self.alert


class _Policy:
    def evaluate(self, alert):
        return alert


class _Notifier:
    def __init__(self):
        self.calls = 0

    def notify(self, _pending, _token):
        self.calls += 1
        return self.calls == 2


class ReactionServiceTests(unittest.TestCase):
    def test_notification_retries_and_records_success(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ReactionStore(Path(directory) / "reaction.db")
            store.register_switch("lab", "http://floodlight:8080", "1", "10.10.0.0/24")
            alert = AlertEvent(
                sid=1001, gid=1, priority=1, msg="test", proto="TCP",
                src_addr="192.0.2.10", src_port=1234,
                dst_addr="10.10.0.25", dst_port=80,
                action="allow", iface="ens3", ts=datetime.now(timezone.utc),
            )
            notifier = _Notifier()
            service = ReactionService(
                tailer=_Tailer(), normalizer=_Normalizer(alert), policy=_Policy(),
                store=store, notifier=notifier, token_ttl_seconds=3600,
                cooldown_seconds=60, email_attempts=3,
            )
            service.run()
            self.assertEqual(notifier.calls, 2)
            with store._connect() as connection:
                row = connection.execute(
                    "SELECT notification_status FROM pending_actions"
                ).fetchone()
            self.assertEqual(row["notification_status"], "sent")


if __name__ == "__main__":
    unittest.main()
