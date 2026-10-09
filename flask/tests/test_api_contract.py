import importlib.util
import sys
import types
import unittest
import unittest.mock
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FLASK_SRC = ROOT / "flask" / "src"
sys.path.insert(0, str(FLASK_SRC))


class _FakeFlask:
    def __init__(self, _name):
        self.extensions = {}

    def register_blueprint(self, _blueprint):
        pass

    def _decorator(self, _path):
        return lambda function: function

    get = _decorator
    post = _decorator
    put = _decorator
    delete = _decorator


fake_flask = types.ModuleType("flask")
fake_flask.Flask = _FakeFlask
fake_flask.jsonify = lambda payload: payload
fake_flask.request = types.SimpleNamespace(get_json=lambda **_kwargs: {})
sys.modules["flask"] = fake_flask

fake_cors = types.ModuleType("flask_cors")
fake_cors.CORS = lambda *_args, **_kwargs: None
sys.modules["flask_cors"] = fake_cors

fake_reaction_routes = types.ModuleType("floodlight_reaction.reaction_routes")
fake_reaction_routes.react_bp = object()
sys.modules["floodlight_reaction.reaction_routes"] = fake_reaction_routes

_db_directory = tempfile.TemporaryDirectory()
spec = importlib.util.spec_from_file_location("rules_app_contract", FLASK_SRC / "app.py")
rules_app = importlib.util.module_from_spec(spec)
with unittest.mock.patch.dict("os.environ", {
    "RULES_DIR": "/tmp/rules",
    "RULES_FILE": "test.rules",
    "SNORT_AGENT_URL": "http://snort-agent",
    "REACTION_DB_PATH": str(Path(_db_directory.name) / "reaction.db"),
}, clear=True):
    spec.loader.exec_module(rules_app)

from models import ServiceResult, ServiceState


class ApiContractTests(unittest.TestCase):
    def test_every_service_state_has_one_http_status(self):
        self.assertEqual(set(rules_app.HTTP_STATUS_BY_STATE), set(ServiceState))
        self.assertEqual(rules_app.HTTP_STATUS_BY_STATE, {
            ServiceState.OK: 200,
            ServiceState.CREATED: 201,
            ServiceState.NOT_FOUND: 404,
            ServiceState.CONFLICT: 409,
            ServiceState.BAD_REQUEST: 400,
            ServiceState.AGENT_ERROR: 502,
            ServiceState.RELOAD_FAILED: 500,
        })

    def test_service_response_uses_central_mapping(self):
        payload, status = rules_app.service_response(
            ServiceResult(ServiceState.CONFLICT, {"error": "duplicate"})
        )
        self.assertEqual(status, 409)
        self.assertEqual(payload, {"error": "duplicate"})

    def test_rules_file_error_exposes_no_internal_metadata(self):
        payload, status = rules_app.rules_file_not_found_response()
        self.assertEqual(status, 404)
        self.assertEqual(payload, {"error": "Rules file not found"})


if __name__ == "__main__":
    unittest.main()
