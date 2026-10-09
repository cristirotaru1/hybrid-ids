import hashlib
import ipaddress
import json
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SwitchRecord:
    id: int
    name: str
    controller_url: str
    dpid: str
    cidr: str
    enabled: bool


@dataclass(frozen=True)
class PendingAction:
    id: int
    sid: int
    priority: int
    msg: str
    proto: str
    src_addr: str
    src_port: int | None
    dst_addr: str
    dst_port: int | None
    alert_ts: str
    switch_id: int
    switch_name: str
    switch_dpid: str
    controller_url: str
    switch_cidr: str
    status: str
    notification_status: str
    created_at: str
    expires_at: str
    last_attempt_at: str | None

    @property
    def is_expired(self) -> bool:
        return utc_now() > datetime.fromisoformat(self.expires_at)


SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS switches (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    controller_url TEXT NOT NULL,
    dpid TEXT NOT NULL,
    cidr TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(controller_url, dpid)
);
CREATE TABLE IF NOT EXISTS pending_actions (
    id INTEGER PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    sid INTEGER NOT NULL,
    priority INTEGER NOT NULL,
    msg TEXT NOT NULL,
    proto TEXT NOT NULL,
    src_addr TEXT NOT NULL,
    src_port INTEGER,
    dst_addr TEXT NOT NULL,
    dst_port INTEGER,
    alert_ts TEXT NOT NULL,
    switch_id INTEGER NOT NULL REFERENCES switches(id),
    status TEXT NOT NULL CHECK (status IN (
        'pending', 'processing', 'used', 'expired', 'partial_failure', 'unblocked'
    )),
    notification_status TEXT NOT NULL CHECK (notification_status IN (
        'pending', 'sent', 'failed'
    )),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_attempt_at TEXT
);
CREATE TABLE IF NOT EXISTS notification_cooldowns (
    sid INTEGER NOT NULL,
    src_addr TEXT NOT NULL,
    dst_addr TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (sid, src_addr, dst_addr)
);
CREATE TABLE IF NOT EXISTS enforcement_attempts (
    id INTEGER PRIMARY KEY,
    pending_id INTEGER NOT NULL REFERENCES pending_actions(id) ON DELETE CASCADE,
    switch_id INTEGER NOT NULL REFERENCES switches(id),
    attempted_at TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('block', 'unblock')),
    result_status TEXT NOT NULL,
    forward_flow TEXT,
    reverse_flow TEXT,
    details TEXT NOT NULL,
    dry_run INTEGER NOT NULL DEFAULT 0 CHECK (dry_run IN (0, 1))
);
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY,
    occurred_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id INTEGER,
    details TEXT NOT NULL
);
"""


class ReactionStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.migrate()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def migrate(self) -> None:
        with self._connect() as connection:
            connection.executescript(SCHEMA)
            connection.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (1, ?)",
                (utc_now().isoformat(),),
            )

    def register_switch(self, name: str, controller_url: str, dpid: str, cidr: str) -> SwitchRecord:
        ipaddress.ip_network(cidr, strict=False)
        now = utc_now().isoformat()
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO switches(name, controller_url, dpid, cidr, enabled, created_at, updated_at)
                   VALUES (?, ?, ?, ?, 1, ?, ?)
                   ON CONFLICT(name) DO UPDATE SET controller_url=excluded.controller_url,
                     dpid=excluded.dpid, cidr=excluded.cidr, updated_at=excluded.updated_at""",
                (name, controller_url.rstrip("/"), dpid, cidr, now, now),
            )
            row = connection.execute("SELECT * FROM switches WHERE name = ?", (name,)).fetchone()
        return self._switch(row)

    def list_switches(self) -> list[SwitchRecord]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM switches ORDER BY id").fetchall()
        return [self._switch(row) for row in rows]

    def resolve_switch(self, src_addr: str, dst_addr: str) -> SwitchRecord:
        enabled = [switch for switch in self.list_switches() if switch.enabled]
        if len(enabled) == 1:
            switch = enabled[0]
            network = ipaddress.ip_network(switch.cidr, strict=False)
            if ipaddress.ip_address(src_addr) not in network and ipaddress.ip_address(dst_addr) not in network:
                raise ValueError(f"Neither endpoint belongs to managed network {switch.cidr}")
            return switch
        matches = []
        for switch in enabled:
            network = ipaddress.ip_network(switch.cidr, strict=False)
            if ipaddress.ip_address(src_addr) in network or ipaddress.ip_address(dst_addr) in network:
                matches.append((network.prefixlen, switch))
        if not matches:
            raise ValueError("No enabled switch manages either alert endpoint")
        best_prefix = max(prefix for prefix, _ in matches)
        best = [switch for prefix, switch in matches if prefix == best_prefix]
        if len(best) != 1:
            raise ValueError("Switch selection is ambiguous")
        return best[0]

    def create_pending(self, alert, ttl_seconds: int, cooldown_seconds: int):
        switch = self.resolve_switch(alert.src_addr, alert.dst_addr)
        now = utc_now()
        cooldown_until = now + timedelta(seconds=cooldown_seconds)
        token = secrets.token_urlsafe(32)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cooldown = connection.execute(
                "SELECT expires_at FROM notification_cooldowns WHERE sid=? AND src_addr=? AND dst_addr=?",
                (alert.sid, alert.src_addr, alert.dst_addr),
            ).fetchone()
            if cooldown and datetime.fromisoformat(cooldown["expires_at"]) > now:
                return None
            connection.execute(
                """INSERT INTO notification_cooldowns(sid, src_addr, dst_addr, expires_at)
                   VALUES (?, ?, ?, ?) ON CONFLICT(sid, src_addr, dst_addr)
                   DO UPDATE SET expires_at=excluded.expires_at""",
                (alert.sid, alert.src_addr, alert.dst_addr, cooldown_until.isoformat()),
            )
            cursor = connection.execute(
                """INSERT INTO pending_actions(
                    token_hash, sid, priority, msg, proto, src_addr, src_port,
                    dst_addr, dst_port, alert_ts, switch_id, status,
                    notification_status, created_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 'pending', ?, ?)""",
                (token_hash(token), alert.sid, alert.priority, alert.msg, alert.proto,
                 alert.src_addr, alert.src_port, alert.dst_addr, alert.dst_port,
                 alert.ts.isoformat(), switch.id, now.isoformat(),
                 (now + timedelta(seconds=ttl_seconds)).isoformat()),
            )
            pending_id = cursor.lastrowid
            self._audit(connection, "pending_created", "pending_action", pending_id,
                        {"sid": alert.sid, "switch_id": switch.id})
        return token, self.get_by_id(pending_id)

    def get_by_token(self, token: str) -> PendingAction | None:
        with self._connect() as connection:
            row = connection.execute(self._pending_query("p.token_hash = ?"), (token_hash(token),)).fetchone()
        return self._pending(row) if row else None

    def get_by_id(self, pending_id: int) -> PendingAction | None:
        with self._connect() as connection:
            row = connection.execute(self._pending_query("p.id = ?"), (pending_id,)).fetchone()
        return self._pending(row) if row else None

    def mark_notification(self, pending_id: int, sent: bool) -> None:
        status = "sent" if sent else "failed"
        with self._connect() as connection:
            connection.execute("UPDATE pending_actions SET notification_status=? WHERE id=?", (status, pending_id))
            self._audit(connection, f"notification_{status}", "pending_action", pending_id, {})

    def claim(self, token: str, operation: str = "block") -> PendingAction | None:
        expected = "pending" if operation == "block" else "used"
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(self._pending_query("p.token_hash = ?"), (token_hash(token),)).fetchone()
            if not row or row["status"] != expected:
                return None
            if datetime.fromisoformat(row["expires_at"]) < utc_now() and operation == "block":
                connection.execute("UPDATE pending_actions SET status='expired' WHERE id=?", (row["id"],))
                return None
            connection.execute(
                "UPDATE pending_actions SET status='processing', last_attempt_at=? WHERE id=?",
                (utc_now().isoformat(), row["id"]),
            )
            row = connection.execute(self._pending_query("p.id = ?"), (row["id"],)).fetchone()
        return self._pending(row)

    def record_attempt(self, pending_id: int, operation: str, result) -> PendingAction:
        now = utc_now().isoformat()
        if operation == "block":
            status = (
                "pending" if result.dry_run else
                "used" if result.success else
                "partial_failure" if result.status == "partial_failure" else
                "pending"
            )
        else:
            status = "used" if result.dry_run else ("unblocked" if result.success else "used")
        installed = list(getattr(result, "installed", []))
        removed = list(getattr(result, "removed", []))
        flows = installed or removed
        with self._connect() as connection:
            row = connection.execute("SELECT switch_id FROM pending_actions WHERE id=?", (pending_id,)).fetchone()
            if not row:
                raise KeyError(f"Pending action {pending_id} does not exist")
            connection.execute("UPDATE pending_actions SET status=?, last_attempt_at=? WHERE id=?", (status, now, pending_id))
            connection.execute(
                """INSERT INTO enforcement_attempts(
                    pending_id, switch_id, attempted_at, operation, result_status,
                    forward_flow, reverse_flow, details, dry_run)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (pending_id, row["switch_id"], now, operation, result.status,
                 flows[0] if flows else None, flows[1] if len(flows) > 1 else None,
                 json.dumps({"errors": result.errors, "verified": getattr(result, "verified", False)}),
                 int(result.dry_run)),
            )
            self._audit(connection, operation, "pending_action", pending_id,
                        {"status": result.status, "dry_run": result.dry_run})
        return self.get_by_id(pending_id)

    def cleanup(self, pending_retention_days: int = 30, audit_retention_days: int = 90) -> dict:
        now = utc_now()
        pending_before = (now - timedelta(days=pending_retention_days)).isoformat()
        audit_before = (now - timedelta(days=audit_retention_days)).isoformat()
        with self._connect() as connection:
            stale_processing = (now - timedelta(minutes=5)).isoformat()
            connection.execute(
                "UPDATE pending_actions SET status='pending' WHERE status='processing' AND last_attempt_at < ?",
                (stale_processing,),
            )
            connection.execute("UPDATE pending_actions SET status='expired' WHERE status='pending' AND expires_at < ?", (now.isoformat(),))
            cooldowns = connection.execute("DELETE FROM notification_cooldowns WHERE expires_at < ?", (now.isoformat(),)).rowcount
            pending = connection.execute("DELETE FROM pending_actions WHERE status IN ('expired','unblocked') AND created_at < ?", (pending_before,)).rowcount
            audits = connection.execute("DELETE FROM audit_events WHERE occurred_at < ?", (audit_before,)).rowcount
        return {"cooldowns_deleted": cooldowns, "pending_deleted": pending, "audit_deleted": audits}

    def import_legacy(self, pending_path: str | Path, audit_path: str | Path) -> dict:
        imported_pending = imported_audit = rejected = 0
        pending_file, audit_file = Path(pending_path), Path(audit_path)
        pending_data = {}
        if pending_file.exists():
            try:
                pending_data = json.loads(pending_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                rejected += 1
        switches = [switch for switch in self.list_switches() if switch.enabled]
        if len(switches) != 1 and pending_data:
            raise ValueError("Legacy import requires exactly one enabled switch")
        with self._connect() as connection:
            for token, entry in pending_data.items():
                try:
                    connection.execute(
                        """INSERT OR IGNORE INTO pending_actions(
                           token_hash,sid,priority,msg,proto,src_addr,src_port,dst_addr,dst_port,
                           alert_ts,switch_id,status,notification_status,created_at,expires_at,last_attempt_at)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (token_hash(token), int(entry["sid"]), int(entry["priority"]), entry.get("msg", ""),
                         entry.get("proto", ""), entry["src_addr"], entry.get("src_port"),
                         entry["dst_addr"], entry.get("dst_port"), entry["alert_ts"], switches[0].id,
                         entry.get("status", "pending"), "sent", entry.get("created_at", entry["alert_ts"]),
                         entry["expires_at"], entry.get("last_attempt_at")),
                    )
                    imported_pending += 1
                except (KeyError, TypeError, ValueError, sqlite3.DatabaseError):
                    rejected += 1
            if audit_file.exists():
                for line in audit_file.read_text(encoding="utf-8").splitlines():
                    try:
                        entry = json.loads(line)
                        entry.pop("token", None)
                        self._audit(connection, entry.get("event", "legacy"), "legacy", None, entry)
                        imported_audit += 1
                    except (json.JSONDecodeError, TypeError):
                        rejected += 1
        return {"pending_imported": imported_pending, "audit_imported": imported_audit, "rejected": rejected}

    @staticmethod
    def _switch(row) -> SwitchRecord:
        return SwitchRecord(row["id"], row["name"], row["controller_url"], row["dpid"], row["cidr"], bool(row["enabled"]))

    @staticmethod
    def _pending_query(where: str) -> str:
        return f"""SELECT p.*, s.name switch_name, s.dpid switch_dpid,
                          s.controller_url, s.cidr switch_cidr
                   FROM pending_actions p JOIN switches s ON s.id=p.switch_id
                   WHERE {where}"""

    @staticmethod
    def _pending(row) -> PendingAction:
        return PendingAction(
            id=row["id"], sid=row["sid"], priority=row["priority"], msg=row["msg"],
            proto=row["proto"], src_addr=row["src_addr"], src_port=row["src_port"],
            dst_addr=row["dst_addr"], dst_port=row["dst_port"], alert_ts=row["alert_ts"],
            switch_id=row["switch_id"], switch_name=row["switch_name"],
            switch_dpid=row["switch_dpid"], controller_url=row["controller_url"],
            switch_cidr=row["switch_cidr"], status=row["status"],
            notification_status=row["notification_status"], created_at=row["created_at"],
            expires_at=row["expires_at"], last_attempt_at=row["last_attempt_at"],
        )

    @staticmethod
    def _audit(connection, event_type: str, entity_type: str, entity_id: int | None, details: dict) -> None:
        connection.execute(
            "INSERT INTO audit_events(occurred_at,event_type,entity_type,entity_id,details) VALUES(?,?,?,?,?)",
            (utc_now().isoformat(), event_type, entity_type, entity_id, json.dumps(details)),
        )
