import os
import signal
import subprocess
import tempfile
from flask import Flask, jsonify, request

app = Flask(__name__)

SNORT_BIN = os.getenv("SNORT_BIN")
SNORT_CONF = os.getenv("SNORT_CONF")
SNORT_RULES = os.getenv("SNORT_RULES")


def read_active_rules():
    active = []
    with open(SNORT_RULES, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#"):
                continue
            active.append(stripped)
    return active


def write_ruleset(rules, file_object):
    """Write exactly one normalized rule per line."""
    file_object.write("\n".join(rules))
    if rules:
        file_object.write("\n")


def validate_rules(rules):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", encoding="utf-8", delete=True) as tmp:
        write_ruleset(rules, tmp)
        tmp.flush()

        cmd = [
            SNORT_BIN,
            "-c", SNORT_CONF,
            "-R", tmp.name,
            "-T",
        ]

        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=20,
        )


def validation_response(result):
    if result.returncode == 0:
        return jsonify({
            "valid": True,
            "message": "Ruleset validated successfully"
        }), 200

    details = (result.stderr or result.stdout or "").strip()
    return jsonify({
        "valid": False,
        "error": "Snort validation failed",
        "details": details
    }), 400


def get_snort_pid():
    result = subprocess.run(
        ["pgrep", "-o", "snort"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError("Could not find running Snort PID")
    return int(result.stdout.strip())


@app.get("/status")
def status():
    try:
        pid = get_snort_pid()
        return jsonify({
            "status": "ok",
            "snort_pid": pid,
            "snort_conf": SNORT_CONF,
            "rules_file": SNORT_RULES
        }), 200
    except Exception as exc:
        return jsonify({
            "status": "error",
            "error": str(exc)
        }), 500


@app.post("/validate-rule")
def validate_rule():
    payload = request.get_json(silent=True) or {}
    raw = (payload.get("raw") or "").strip()

    if not raw:
        return jsonify({
            "valid": False,
            "error": "Rule text cannot be empty"
        }), 400

    result = validate_rules(read_active_rules() + [raw])
    return validation_response(result)


@app.post("/validate-ruleset")
def validate_ruleset():
    payload = request.get_json(silent=True) or {}
    rules = payload.get("rules")

    if not isinstance(rules, list) or any(not isinstance(rule, str) for rule in rules):
        return jsonify({
            "valid": False,
            "error": "Rules must be provided as a list of strings"
        }), 400

    normalized = [rule.strip() for rule in rules if rule.strip()]
    result = validate_rules(normalized)
    return validation_response(result)


@app.post("/reload")
def reload_snort():
    try:
        pid = get_snort_pid()
        os.kill(pid, signal.SIGHUP)
        return jsonify({
            "reloaded": True,
            "message": "Snort reload signal sent successfully",
            "snort_pid": pid
        }), 200
    except Exception as exc:
        return jsonify({
            "reloaded": False,
            "error": str(exc)
        }), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
