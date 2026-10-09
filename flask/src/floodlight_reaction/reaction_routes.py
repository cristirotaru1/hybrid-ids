import hashlib
import ipaddress
import time
from dataclasses import asdict
from urllib.parse import urlparse

from flask import Blueprint, abort, current_app, redirect, render_template_string, request, url_for

from config import AppConfig
from reaction_common import ReactionStore
from .floodlight_executor import FloodlightExecutor


react_bp = Blueprint("react", __name__, url_prefix="/react")
_attempt_windows: dict[str, list[float]] = {}


def _runtime_config() -> AppConfig:
    return current_app.extensions["app_config"]


def _store() -> ReactionStore:
    return current_app.extensions["reaction_store"]


def _build_executor(config: AppConfig | None = None, action=None) -> FloodlightExecutor:
    config = config or AppConfig.from_env(require_rules=False)
    if action is None:
        config.require_floodlight()
        host, port, dpid = config.floodlight_host, config.floodlight_port, config.switch_dpid
    else:
        parsed = urlparse(action.controller_url)
        if parsed.scheme != "http" or not parsed.hostname:
            raise ValueError("Switch controller URL must be an HTTP URL")
        host, port, dpid = parsed.hostname, parsed.port or 80, action.switch_dpid
    return FloodlightExecutor(host, port, dpid, dry_run=config.react_dry_run)


def _validate_scope(action) -> None:
    network = ipaddress.ip_network(action.switch_cidr, strict=False)
    if ipaddress.ip_address(action.src_addr) not in network and ipaddress.ip_address(action.dst_addr) not in network:
        raise ValueError(f"Neither endpoint belongs to managed network {action.switch_cidr}")


def _rate_limit(token: str) -> None:
    now = time.monotonic()
    key = hashlib.sha256(token.encode()).hexdigest()
    recent = [timestamp for timestamp in _attempt_windows.get(key, []) if now - timestamp < 60]
    if len(recent) >= 10:
        abort(429, description="Too many reaction attempts; retry later.")
    recent.append(now)
    _attempt_windows[key] = recent


def _record_result(entry: dict, result, attempt_time: str) -> None:
    """Compatibility helper retained for unit-level state tests."""
    entry["last_attempt_at"] = attempt_time
    entry["last_result"] = asdict(result)
    if result.dry_run:
        entry["status"] = "pending"
    elif result.success:
        entry["status"] = "used"
    elif result.status == "partial_failure":
        entry["status"] = "partial_failure"
    else:
        entry["status"] = "pending"


_CONFIRM_PAGE = """
<!doctype html><html><body style="font-family:Arial;max-width:650px;margin:50px auto">
<h2>Priority-{{ entry.priority }} Snort alert</h2>
<table cellpadding="7">
<tr><th align="left">Signature</th><td>{{ entry.msg }} (sid={{ entry.sid }})</td></tr>
<tr><th align="left">Traffic</th><td>{{ entry.src_addr }}:{{ entry.src_port }} → {{ entry.dst_addr }}:{{ entry.dst_port }}</td></tr>
<tr><th align="left">Switch</th><td>{{ entry.switch_name }} ({{ entry.switch_dpid }})</td></tr>
<tr><th align="left">Managed network</th><td>{{ entry.switch_cidr }}</td></tr>
<tr><th align="left">Status</th><td>{{ display_status }}</td></tr>
</table>
{% if display_status == 'pending' %}
<form method="post" action="{{ url_for('react.block', token=token) }}">
<button type="submit">Block this traffic</button></form>
{% elif display_status == 'used' %}
<form method="post" action="{{ url_for('react.unblock', token=token) }}">
<button type="submit">Unblock this traffic</button></form>
{% elif display_status == 'partial_failure' %}
<p><strong>Manual review required:</strong> a partial flow state may remain.</p>
{% endif %}
</body></html>
"""


_RESULT_PAGE = """
<!doctype html><html><body style="font-family:Arial;max-width:650px;margin:50px auto">
<h2>{{ operation|capitalize }} result: {{ result.status }}</h2>
{% if result.dry_run %}<p><strong>Simulation only:</strong> no Floodlight flows were changed.</p>{% endif %}
<p>Switch: {{ entry.switch_name }} ({{ entry.switch_dpid }})</p>
<p>Verified by controller: {{ result.verified }}</p>
{% if result.installed is defined %}<p>Flows: {{ result.installed|join(', ') }}</p>{% endif %}
{% if result.removed is defined %}<p>Flows: {{ result.removed|join(', ') }}</p>{% endif %}
{% if result.errors %}<p>Errors: {{ result.errors|join('; ') }}</p>{% endif %}
<p><a href="{{ url_for('react.confirm', token=token) }}">Return to action</a></p>
</body></html>
"""


@react_bp.get("/confirm/<token>")
def confirm(token: str):
    _rate_limit(token)
    action = _store().get_by_token(token)
    if action is None:
        abort(404, description="Unknown token.")
    display_status = "expired" if action.is_expired and action.status == "pending" else action.status
    return render_template_string(
        _CONFIRM_PAGE, entry=action, display_status=display_status, token=token
    )


def _execute(token: str, operation: str):
    _rate_limit(token)
    candidate = _store().get_by_token(token)
    if candidate is None:
        abort(404, description="Unknown token.")
    try:
        _validate_scope(candidate)
        executor = _build_executor(_runtime_config(), candidate)
    except (TypeError, ValueError, RuntimeError) as exc:
        abort(422, description=f"Invalid reaction request: {exc}")
    action = _store().claim(token, operation)
    if action is None:
        return redirect(url_for("react.confirm", token=token))
    result = (
        executor.block(action.sid, action.src_addr, action.dst_addr)
        if operation == "block"
        else executor.unblock(action.sid, action.src_addr, action.dst_addr)
    )
    updated = _store().record_attempt(action.id, operation, result)
    return render_template_string(
        _RESULT_PAGE, entry=updated, result=result, operation=operation, token=token
    )


@react_bp.post("/block/<token>")
def block(token: str):
    return _execute(token, "block")


@react_bp.post("/unblock/<token>")
def unblock(token: str):
    return _execute(token, "unblock")
