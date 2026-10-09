"""Coordinate alert filtering, persistence, and operator notification."""

import logging
from adapters.alert_tailer import AlertTailer
from adapters.alert_normalizer import AlertNormalizer
from adapters.email_notifier import EmailNotifier
from domain.response_policy import ResponsePolicy
from reaction_common import ReactionStore

logger = logging.getLogger(__name__)


class ReactionService:
    def __init__(
        self,
        tailer: AlertTailer,
        normalizer: AlertNormalizer,
        policy: ResponsePolicy,
        store: ReactionStore,
        notifier: EmailNotifier,
        token_ttl_seconds: int,
        cooldown_seconds: int,
        email_attempts: int = 3,
    ):
        self._tailer = tailer
        self._normalizer = normalizer
        self._policy = policy
        self._store = store
        self._notifier = notifier
        self._token_ttl_seconds = token_ttl_seconds
        self._cooldown_seconds = cooldown_seconds
        self._email_attempts = email_attempts

    def run(self) -> None:
        """Process incoming alerts continuously."""
        logger.info("ReactionService started, waiting for alerts...")

        for raw_line in self._tailer.tail():
            alert = self._normalizer.parse(raw_line)
            if alert is None:
                continue

            logger.debug("Alert received: sid=%d priority=%d src=%s dst=%s",
                         alert.sid, alert.priority, alert.src_addr, alert.dst_addr)

            should_notify = self._policy.evaluate(alert)
            if should_notify is None:
                logger.debug("Alert sid=%d ignored by policy", alert.sid)
                continue

            created = self._store.create_pending(
                alert,
                ttl_seconds=self._token_ttl_seconds,
                cooldown_seconds=self._cooldown_seconds,
            )
            if created is None:
                logger.debug("Alert sid=%d ignored by persistent cooldown", alert.sid)
                continue

            token, pending = created
            email_sent = False
            for attempt in range(1, self._email_attempts + 1):
                if self._notifier.notify(pending, token):
                    email_sent = True
                    break
                logger.warning("Email attempt %d/%d failed for pending action %d",
                               attempt, self._email_attempts, pending.id)
            self._store.mark_notification(pending.id, email_sent)

            if email_sent:
                logger.info(
                    "Operator notified: sid=%d %s -> %s (pending_id=%d, expires=%s)",
                    alert.sid, alert.src_addr, alert.dst_addr,
                    pending.id, pending.expires_at,
                )
            else:
                logger.error(
                    "Notification FAILED for sid=%d %s -> %s -- pending entry "
                    "still created (pending_id=%d), operator must be alerted some "
                    "other way or will see it on next dashboard check",
                    alert.sid, alert.src_addr, alert.dst_addr, pending.id,
                )
