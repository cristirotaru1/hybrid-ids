from flask import Flask, jsonify, request
from flask_cors import CORS
from config import AppConfig
from models import ServiceResult, ServiceState
from repository import RulesRepository
from service import RulesService
from floodlight_reaction.reaction_routes import react_bp
from reaction_common import ReactionStore

def create_app(config: AppConfig | None = None) -> Flask:
    runtime_config = config or AppConfig.from_env()
    flask_app = Flask(__name__)
    flask_app.extensions["app_config"] = runtime_config
    reaction_store = ReactionStore(runtime_config.reaction_db_path)
    if runtime_config.floodlight_host and runtime_config.switch_dpid:
        reaction_store.register_switch(
            runtime_config.switch_name,
            f"http://{runtime_config.floodlight_host}:{runtime_config.floodlight_port}",
            runtime_config.switch_dpid,
            runtime_config.switch_cidr,
        )
    flask_app.extensions["reaction_store"] = reaction_store
    flask_app.extensions["rules_service"] = RulesService(
        repository=RulesRepository(runtime_config.rules_dir, runtime_config.rules_file),
        snort_agent_url=runtime_config.snort_agent_url,
    )
    flask_app.register_blueprint(react_bp)

    CORS(
        flask_app,
        resources={
            r"/rules/*": {
                "origins": ["http://192.168.122.13:3000"],
                "methods": ["POST", "OPTIONS", "PUT", "DELETE"],
                "allow_headers": ["Content-Type", "x-grafana-action", "x-grafana-device-id"],
            },
            r"/rules": {
                "origins": ["http://192.168.122.13:3000"],
                "methods": ["GET", "POST", "OPTIONS"],
                "allow_headers": ["Content-Type"],
            },
        },
    )
    return flask_app


app = create_app()
rules_service = app.extensions["rules_service"]

HTTP_STATUS_BY_STATE = {
    ServiceState.OK: 200,
    ServiceState.CREATED: 201,
    ServiceState.NOT_FOUND: 404,
    ServiceState.CONFLICT: 409,
    ServiceState.BAD_REQUEST: 400,
    ServiceState.AGENT_ERROR: 502,
    ServiceState.RELOAD_FAILED: 500,
}


def service_response(result: ServiceResult):
    return jsonify(result.payload), HTTP_STATUS_BY_STATE[result.state]


def rules_file_not_found_response():
    return jsonify({"error": "Rules file not found"}), 404

@app.get("/")
def index():
    return jsonify({"message": "Flask API is running"})


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.get("/rules")
def get_rules():
    try:
        rules = rules_service.list_rule_summaries()
    except FileNotFoundError:
        return rules_file_not_found_response()

    return jsonify({
        "count": len(rules),
        "rules": rules
    }), 200

@app.get("/rules/<int:sid>")
def get_rule_by_sid(sid: int):
    try:
        result = rules_service.get_rule_detail_by_sid(sid)
    except FileNotFoundError:
        return rules_file_not_found_response()

    return service_response(result)

@app.put("/rules/<int:sid>")
def update_rule_by_sid(sid: int):
    try:
        payload = request.get_json(silent=True) or {}
        raw_rule = payload.get("raw")
        result = rules_service.update_rule_by_sid(sid, raw_rule)
    except FileNotFoundError:
        return rules_file_not_found_response()

    return service_response(result)

@app.delete("/rules/<int:sid>")
def delete_rule_by_sid(sid: int):
    try:
        result = rules_service.disable_rule_by_sid(sid)
    except FileNotFoundError:
        return rules_file_not_found_response()

    return service_response(result)

@app.post("/rules")
def create_rule():
    try:
        payload = request.get_json(silent=True) or {}
        raw_rule = payload.get("raw")
        result = rules_service.create_rule_from_raw(raw_rule)
    except FileNotFoundError:
        return rules_file_not_found_response()

    return service_response(result)

@app.post("/rules/<int:sid>/disable")
def disable_rule_by_sid(sid: int):
    try:
        result = rules_service.disable_rule_by_sid(sid)
    except FileNotFoundError:
        return rules_file_not_found_response()

    return service_response(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
