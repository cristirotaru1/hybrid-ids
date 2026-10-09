"""Apply confirmed traffic blocks through Floodlight."""

import json
import ipaddress
import logging
import urllib.request
import urllib.error
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_PUSH_URL_TEMPLATE = "http://{host}:{port}/wm/staticflowpusher/json"


@dataclass(frozen=True)
class BlockResult:
    success: bool
    status: str
    installed: list[str] = field(default_factory=list)
    rolled_back: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    dry_run: bool = False
    verified: bool = False


@dataclass(frozen=True)
class UnblockResult:
    success: bool
    status: str
    removed: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    dry_run: bool = False
    verified: bool = False


class FloodlightExecutor:
    def __init__(self, host: str, port: int, switch_dpid: str, dry_run: bool = False):
        self._url = _PUSH_URL_TEMPLATE.format(host=host, port=port)
        self._dpid = switch_dpid
        self._dry_run = dry_run

    def block(self, sid: int, src_ip: str, dst_ip: str) -> BlockResult:
        """Install two DROP rules and roll back a partial installation."""
        self._validate_inputs(sid, src_ip, dst_ip)
        fwd_rule = self._build_rule(
            name=f"reaction-{src_ip}-{dst_ip}-{sid}-fwd",
            src_ip=src_ip,
            dst_ip=dst_ip,
        )
        rev_rule = self._build_rule(
            name=f"reaction-{dst_ip}-{src_ip}-{sid}-rev",
            src_ip=dst_ip,
            dst_ip=src_ip,
        )

        if self._dry_run:
            logger.info("[DRY-RUN] Would push flow: %s", json.dumps(fwd_rule))
            logger.info("[DRY-RUN] Would push flow: %s", json.dumps(rev_rule))
            return BlockResult(
                success=True, status="dry_run",
                installed=[fwd_rule["name"], rev_rule["name"]], dry_run=True,
            )

        ok_fwd, fwd_error = self._push_flow(fwd_rule)
        if not ok_fwd:
            return BlockResult(
                success=False,
                status="failed",
                errors=[fwd_error],
            )

        ok_rev, rev_error = self._push_flow(rev_rule)
        if ok_rev:
            verified, verify_error = self._verify_flows([fwd_rule["name"], rev_rule["name"]], present=True)
            if not verified:
                return BlockResult(
                    success=False, status="partial_failure",
                    installed=[fwd_rule["name"], rev_rule["name"]],
                    errors=[verify_error],
                )
            return BlockResult(
                success=True,
                status="success",
                installed=[fwd_rule["name"], rev_rule["name"]],
                verified=True,
            )

        rollback_ok, rollback_error = self._delete_flow(fwd_rule["name"])
        if rollback_ok:
            rollback_verified, verify_error = self._verify_flows([fwd_rule["name"]], present=False)
            if not rollback_verified:
                return BlockResult(
                    success=False,
                    status="partial_failure",
                    installed=[fwd_rule["name"]],
                    errors=[rev_error, verify_error],
                )
            return BlockResult(
                success=False,
                status="rolled_back",
                rolled_back=[fwd_rule["name"]],
                errors=[rev_error],
            )

        return BlockResult(
            success=False,
            status="partial_failure",
            installed=[fwd_rule["name"]],
            errors=[rev_error, rollback_error],
        )

    def unblock(self, sid: int, src_ip: str, dst_ip: str) -> UnblockResult:
        self._validate_inputs(sid, src_ip, dst_ip)
        names = [
            f"reaction-{src_ip}-{dst_ip}-{sid}-fwd",
            f"reaction-{dst_ip}-{src_ip}-{sid}-rev",
        ]
        if self._dry_run:
            return UnblockResult(True, "dry_run", removed=names, dry_run=True)
        removed, errors = [], []
        for name in names:
            ok, error = self._delete_flow(name)
            if ok:
                removed.append(name)
            else:
                errors.append(error)
        verified, verify_error = self._verify_flows(names, present=False)
        if not verified:
            errors.append(verify_error)
        success = len(removed) == 2 and verified
        return UnblockResult(
            success=success,
            status="success" if success else "partial_failure",
            removed=removed,
            errors=errors,
            verified=verified,
        )

    @staticmethod
    def _validate_inputs(sid: int, src_ip: str, dst_ip: str) -> None:
        if isinstance(sid, bool) or not isinstance(sid, int) or sid <= 0:
            raise ValueError("sid must be a positive integer")
        for field_name, value in (("src_ip", src_ip), ("dst_ip", dst_ip)):
            try:
                parsed = ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValueError(f"{field_name} must be a valid IPv4 address") from exc
            if parsed.version != 4:
                raise ValueError(f"{field_name} must be a valid IPv4 address")

    def _build_rule(self, name: str, src_ip: str, dst_ip: str) -> dict:
        """Build a high-priority Floodlight DROP rule."""
        return {
            "switch": self._dpid,
            "name": name,
            "priority": "32768",
            "eth_type": "0x0800",
            "ipv4_src": src_ip,
            "ipv4_dst": dst_ip,
            "active": "true",
            "actions": "",  # Floodlight represents DROP with no actions.
        }

    def _push_flow(self, rule: dict) -> tuple[bool, str | None]:
        payload = json.dumps(rule).encode("utf-8")
        req = urllib.request.Request(
            self._url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode()
                logger.info("Flow installed: %s -> %s", rule["name"], body)
                return True, None
        except urllib.error.HTTPError as exc:
            error = f"Floodlight HTTP {exc.code} while installing {rule['name']}: {exc.read().decode(errors='replace')}"
            logger.error("%s", error)
            return False, error
        except (urllib.error.URLError, OSError) as exc:
            error = f"Floodlight connection error while installing {rule['name']}: {exc}"
            logger.error("%s", error)
            return False, error

    def _delete_flow(self, flow_name: str) -> tuple[bool, str | None]:
        payload = json.dumps({"name": flow_name}).encode("utf-8")
        req = urllib.request.Request(
            self._url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="DELETE",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode()
                logger.info("Flow rolled back: %s -> %s", flow_name, body)
                return True, None
        except urllib.error.HTTPError as exc:
            error = f"Floodlight HTTP {exc.code} while deleting {flow_name}: {exc.read().decode(errors='replace')}"
            logger.error("%s", error)
            return False, error
        except (urllib.error.URLError, OSError) as exc:
            error = f"Floodlight connection error while deleting {flow_name}: {exc}"
            logger.error("%s", error)
            return False, error

    def _verify_flows(self, flow_names: list[str], present: bool) -> tuple[bool, str | None]:
        list_url = self._url.replace(
            "/wm/staticflowpusher/json",
            f"/wm/staticflowpusher/list/{self._dpid}/json",
        )
        try:
            with urllib.request.urlopen(list_url, timeout=5) as response:
                body = response.read().decode()
                data = json.loads(body)
        except (urllib.error.HTTPError, urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            return False, f"Could not verify Floodlight flows: {exc}"
        serialized = json.dumps(data)
        found = [name for name in flow_names if name in serialized]
        if present and len(found) != len(flow_names):
            return False, f"Floodlight did not report all installed flows: {found}"
        if not present and found:
            return False, f"Floodlight still reports removed flows: {found}"
        return True, None
