import importlib.util
import os
import sys
import tempfile
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
FLASK_SRC = ROOT / "flask" / "src"
REACTION_SRC = ROOT / "reaction-service"
sys.path.insert(0, str(FLASK_SRC))
sys.path.insert(0, str(REACTION_SRC))
sys.path.insert(0, str(ROOT))

from floodlight_reaction.floodlight_executor import BlockResult, FloodlightExecutor
from config import AppConfig, ConfigError
from domain.alert_event import AlertEvent
from reaction_common import ReactionStore


class ScriptedExecutor(FloodlightExecutor):
    def __init__(self, pushes, delete=(True, None), dry_run=False, verify=(True, None)):
        super().__init__("floodlight", 8080, "00:00:00:00:00:00:00:01", dry_run=dry_run)
        self.pushes = list(pushes)
        self.delete_result = delete
        self.deleted = []
        self.verify_result = verify

    def _push_flow(self, rule):
        return self.pushes.pop(0)

    def _delete_flow(self, flow_name):
        self.deleted.append(flow_name)
        return self.delete_result

    def _verify_flows(self, flow_names, present):
        return self.verify_result


class _FakeBlueprint:
    def __init__(self, *_args, **_kwargs):
        pass

    def route(self, _path, methods=None):
        return lambda function: function

    get = route
    post = route


fake_flask = types.ModuleType("flask")
fake_flask.Blueprint = _FakeBlueprint
fake_flask.render_template_string = lambda template, **context: (template, context)
fake_flask.abort = lambda status, description=None: (_ for _ in ()).throw(RuntimeError((status, description)))
fake_flask.redirect = lambda value: value
fake_flask.url_for = lambda endpoint, **values: (endpoint, values)
fake_flask.current_app = types.SimpleNamespace(extensions={})
fake_flask.request = types.SimpleNamespace(remote_addr="127.0.0.1")
sys.modules["flask"] = fake_flask

route_spec = importlib.util.spec_from_file_location(
    "floodlight_reaction.reaction_routes_under_test",
    FLASK_SRC / "floodlight_reaction" / "reaction_routes.py",
)
reaction_routes = importlib.util.module_from_spec(route_spec)
route_spec.loader.exec_module(reaction_routes)


class FloodlightExecutorTests(unittest.TestCase):
    def test_successful_bidirectional_block(self):
        result = ScriptedExecutor([(True, None), (True, None)]).block(10, "10.0.0.1", "10.0.0.2")
        self.assertTrue(result.success)
        self.assertEqual(result.status, "success")
        self.assertEqual(len(result.installed), 2)

    def test_first_push_failure_needs_no_rollback(self):
        executor = ScriptedExecutor([(False, "forward failed")])
        result = executor.block(10, "10.0.0.1", "10.0.0.2")
        self.assertFalse(result.success)
        self.assertEqual(result.status, "failed")
        self.assertEqual(executor.deleted, [])

    def test_second_push_failure_rolls_back_forward_flow(self):
        executor = ScriptedExecutor([(True, None), (False, "reverse failed")])
        result = executor.block(10, "10.0.0.1", "10.0.0.2")
        self.assertEqual(result.status, "rolled_back")
        self.assertEqual(result.rolled_back, executor.deleted)
        self.assertEqual(len(result.rolled_back), 1)

    def test_failed_rollback_is_explicit_partial_failure(self):
        executor = ScriptedExecutor(
            [(True, None), (False, "reverse failed")],
            delete=(False, "rollback failed"),
        )
        result = executor.block(10, "10.0.0.1", "10.0.0.2")
        self.assertEqual(result.status, "partial_failure")
        self.assertEqual(len(result.installed), 1)
        self.assertEqual(result.errors, ["reverse failed", "rollback failed"])

    def test_unverified_rollback_is_partial_failure(self):
        executor = ScriptedExecutor(
            [(True, None), (False, "reverse failed")],
            verify=(False, "flow still present"),
        )
        result = executor.block(10, "10.0.0.1", "10.0.0.2")
        self.assertEqual(result.status, "partial_failure")
        self.assertIn("flow still present", result.errors)

    def test_dry_run_has_structured_result_without_network_calls(self):
        with patch("urllib.request.urlopen") as urlopen:
            result = FloodlightExecutor("floodlight", 8080, "1", dry_run=True).block(
                10, "10.0.0.1", "10.0.0.2"
            )
            urlopen.assert_not_called()
        self.assertTrue(result.success)
        self.assertTrue(result.dry_run)
        self.assertEqual(result.status, "dry_run")
        self.assertFalse(result.verified)
        self.assertEqual(len(result.installed), 2)

    def test_invalid_identifiers_are_rejected(self):
        executor = ScriptedExecutor([])
        for sid, src, dst in ((0, "10.0.0.1", "10.0.0.2"), (1, "bad", "10.0.0.2"), (1, "10.0.0.1", "::1")):
            with self.subTest(sid=sid, src=src, dst=dst):
                with self.assertRaises(ValueError):
                    executor.block(sid, src, dst)

    def test_dry_run_unblock_does_not_call_controller(self):
        with patch("urllib.request.urlopen") as urlopen:
            result = FloodlightExecutor("floodlight", 8080, "1", dry_run=True).unblock(
                10, "10.0.0.1", "10.0.0.2"
            )
            urlopen.assert_not_called()
        self.assertEqual(result.status, "dry_run")
        self.assertTrue(result.dry_run)
        self.assertEqual(len(result.removed), 2)


class ReactionRouteStateTests(unittest.TestCase):
    def setUp(self):
        self.entry = {
            "sid": 10,
            "priority": 1,
            "msg": "test",
            "proto": "TCP",
            "src_addr": "10.0.0.1",
            "src_port": 1234,
            "dst_addr": "10.0.0.2",
            "dst_port": 80,
            "alert_ts": datetime.now(timezone.utc).isoformat(),
            "expires_at": datetime.now(timezone.utc).replace(year=2099).isoformat(),
            "status": "pending",
        }

    def test_success_becomes_used(self):
        reaction_routes._record_result(self.entry, BlockResult(True, "success"), "now")
        self.assertEqual(self.entry["status"], "used")

    def test_clean_failure_remains_retryable(self):
        reaction_routes._record_result(self.entry, BlockResult(False, "rolled_back"), "now")
        self.assertEqual(self.entry["status"], "pending")

    def test_partial_failure_is_not_automatically_retryable(self):
        reaction_routes._record_result(self.entry, BlockResult(False, "partial_failure"), "now")
        self.assertEqual(self.entry["status"], "partial_failure")

    def test_scope_rejects_traffic_outside_managed_network(self):
        action = types.SimpleNamespace(
            switch_cidr="10.10.0.0/24",
            src_addr="192.0.2.1",
            dst_addr="198.51.100.2",
        )
        with self.assertRaisesRegex(ValueError, "Neither endpoint"):
            reaction_routes._validate_scope(action)

    def test_import_does_not_require_floodlight_environment(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ConfigError, "FLOODLIGHT_HOST"):
                reaction_routes._build_executor()


class AppConfigTests(unittest.TestCase):
    def test_required_rules_configuration_is_validated(self):
        with self.assertRaisesRegex(ConfigError, "RULES_DIR"):
            AppConfig.from_env({})

    def test_floodlight_is_optional_until_enforcement(self):
        config = AppConfig.from_env({
            "RULES_DIR": "/rules",
            "RULES_FILE": "test.rules",
            "SNORT_AGENT_URL": "http://snort-agent/",
        })
        self.assertIsNone(config.floodlight_host)
        self.assertEqual(config.snort_agent_url, "http://snort-agent")
        self.assertTrue(config.react_dry_run)
        with self.assertRaises(ConfigError):
            config.require_floodlight()

    def test_invalid_port_and_boolean_are_rejected(self):
        base = {
            "RULES_DIR": "/rules",
            "RULES_FILE": "test.rules",
            "SNORT_AGENT_URL": "http://snort-agent",
        }
        with self.assertRaisesRegex(ConfigError, "FLOODLIGHT_PORT"):
            AppConfig.from_env({**base, "FLOODLIGHT_PORT": "bad"})
        with self.assertRaisesRegex(ConfigError, "REACT_DRY_RUN"):
            AppConfig.from_env({**base, "REACT_DRY_RUN": "sometimes"})


class ReactionStoreTests(unittest.TestCase):
    def test_store_persists_switch_pending_action_and_cooldown(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ReactionStore(Path(directory) / "reaction.db")
            store.register_switch("lab", "http://floodlight:8080", "1", "10.10.0.0/24")
            alert = AlertEvent(
                sid=1, gid=1, priority=1, msg="test", proto="TCP",
                src_addr="192.0.2.1", src_port=1,
                dst_addr="10.10.0.2", dst_port=2,
                action="allow", iface="ens3", ts=datetime.now(timezone.utc),
            )
            created = store.create_pending(alert, ttl_seconds=3600, cooldown_seconds=60)
            self.assertIsNotNone(created)
            token, pending = created
            self.assertEqual(store.get_by_token(token).switch_name, "lab")
            self.assertIsNone(store.create_pending(alert, 3600, 60))

    def test_dry_run_does_not_mark_action_used(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ReactionStore(Path(directory) / "reaction.db")
            store.register_switch("lab", "http://floodlight:8080", "1", "10.10.0.0/24")
            alert = AlertEvent(
                sid=1, gid=1, priority=1, msg="test", proto="TCP",
                src_addr="10.10.0.1", src_port=1,
                dst_addr="10.10.0.2", dst_port=2,
                action="allow", iface="ens3", ts=datetime.now(timezone.utc),
            )
            token, pending = store.create_pending(alert, 3600, 60)
            claimed = store.claim(token)
            result = ScriptedExecutor([], dry_run=True).block(1, alert.src_addr, alert.dst_addr)
            restored = store.record_attempt(claimed.id, "block", result)
            self.assertEqual(restored.status, "pending")

    def test_token_is_hashed_and_claim_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ReactionStore(Path(directory) / "reaction.db")
            store.register_switch("lab", "http://floodlight:8080", "1", "10.10.0.0/24")
            alert = AlertEvent(
                sid=2, gid=1, priority=1, msg="test", proto="TCP",
                src_addr="10.10.0.1", src_port=1, dst_addr="10.10.0.2", dst_port=2,
                action="allow", iface="ens3", ts=datetime.now(timezone.utc),
            )
            token, _ = store.create_pending(alert, 3600, 60)
            database_bytes = (Path(directory) / "reaction.db").read_bytes()
            self.assertNotIn(token.encode(), database_bytes)
            self.assertIsNotNone(store.claim(token))
            self.assertIsNone(store.claim(token))

    def test_multiple_switches_use_unique_longest_cidr_match(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ReactionStore(Path(directory) / "reaction.db")
            store.register_switch("wide", "http://floodlight:8080", "1", "10.0.0.0/8")
            store.register_switch("lab", "http://floodlight:8080", "2", "10.10.0.0/24")
            selected = store.resolve_switch("192.0.2.1", "10.10.0.25")
            self.assertEqual(selected.name, "lab")

    def test_cleanup_removes_expired_cooldown(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ReactionStore(Path(directory) / "reaction.db")
            store.register_switch("lab", "http://floodlight:8080", "1", "10.10.0.0/24")
            with store._connect() as connection:
                connection.execute(
                    "INSERT INTO notification_cooldowns VALUES (1, 'a', 'b', '2000-01-01T00:00:00+00:00')"
                )
            result = store.cleanup()
            self.assertEqual(result["cooldowns_deleted"], 1)


if __name__ == "__main__":
    unittest.main()
