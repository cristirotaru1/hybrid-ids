import io
import os
import stat
import sys
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FLASK_SRC = ROOT / "flask" / "src"
SNORT_AGENT = ROOT / "snort" / "agent"
sys.path.insert(0, str(FLASK_SRC))
sys.path.insert(0, str(SNORT_AGENT))


class _FakeFlask:
    def __init__(self, _name):
        pass

    def get(self, _path):
        return lambda function: function

    def post(self, _path):
        return lambda function: function


fake_flask = types.ModuleType("flask")
fake_flask.Flask = _FakeFlask
fake_flask.jsonify = lambda payload: payload
fake_flask.request = types.SimpleNamespace(get_json=lambda **_kwargs: {})
sys.modules["flask"] = fake_flask

from agent import write_ruleset
from models import ServiceState
from repository import RulesRepository
from service import RulesService


RULE_ONE = 'alert icmp any any -> any any (msg:"one"; sid:100001; rev:1;)'
RULE_ONE_UPDATED = 'alert icmp any any -> any any (msg:"updated"; sid:100001; rev:2;)'
RULE_TWO = 'alert tcp any any -> any any (msg:"two"; sid:100002; rev:1;)'


class FakeRulesService(RulesService):
    def __init__(self, repository, reload_results=None):
        self.repository = repository
        self.snort_agent_url = "http://snort-agent"
        self.validated_rulesets = []
        self.reload_results = list(reload_results or [(200, {"reloaded": True})])

    def validate_rules_with_snort(self, rules):
        self.validated_rulesets.append(list(rules))
        return 200, {"valid": True}

    def reload_snort(self):
        if len(self.reload_results) > 1:
            return self.reload_results.pop(0)
        return self.reload_results[0]


class CrudSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.rules_path = Path(self.temp_dir.name) / "test.rules"
        self.rules_path.write_text(RULE_ONE + "\n" + RULE_TWO + "\n", encoding="utf-8")
        os.chmod(self.rules_path, 0o640)

        self.repository = RulesRepository(Path(self.temp_dir.name), "test.rules")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_agent_writes_one_rule_per_line(self):
        output = io.StringIO()
        write_ruleset([RULE_ONE, RULE_TWO], output)
        self.assertEqual(output.getvalue(), RULE_ONE + "\n" + RULE_TWO + "\n")

    def test_atomic_replace_preserves_permissions(self):
        original_stat = self.rules_path.stat()
        self.repository.replace_line(1, RULE_ONE_UPDATED)
        replaced_stat = self.rules_path.stat()
        self.assertEqual(stat.S_IMODE(replaced_stat.st_mode), 0o640)
        self.assertEqual(replaced_stat.st_uid, original_stat.st_uid)
        self.assertEqual(replaced_stat.st_gid, original_stat.st_gid)
        self.assertEqual(self.rules_path.read_text(encoding="utf-8"), RULE_ONE_UPDATED + "\n" + RULE_TWO + "\n")

    def test_snapshot_restore_is_exact(self):
        original = self.repository.snapshot()
        self.repository.comment_line(1)
        self.repository.restore(original)
        self.assertEqual(self.rules_path.read_bytes(), original)

    def test_create_validates_prospective_ruleset_and_persists(self):
        service = FakeRulesService(self.repository)
        rule_three = 'alert udp any any -> any any (msg:"three"; sid:100003; rev:1;)'
        result = service.create_rule_from_raw(rule_three)
        self.assertEqual(result.state, ServiceState.CREATED)
        self.assertEqual(service.validated_rulesets, [[RULE_ONE, RULE_TWO, rule_three]])
        self.assertIn(rule_three, self.rules_path.read_text(encoding="utf-8"))
        self.assertEqual(result.payload["sid"], 100003)
        self.assertTrue({"path", "rules_dir", "rules_file", "snort_agent_url"}.isdisjoint(result.payload))

    def test_update_validates_replacement_not_duplicate(self):
        service = FakeRulesService(self.repository)
        result = service.update_rule_by_sid(100001, RULE_ONE_UPDATED)
        self.assertEqual(result.state, ServiceState.OK)
        self.assertEqual(service.validated_rulesets, [[RULE_ONE_UPDATED, RULE_TWO]])
        self.assertEqual(self.rules_path.read_text(encoding="utf-8"), RULE_ONE_UPDATED + "\n" + RULE_TWO + "\n")

    def test_disable_validates_ruleset_without_selected_rule(self):
        service = FakeRulesService(self.repository)
        result = service.disable_rule_by_sid(100001)
        self.assertEqual(result.state, ServiceState.OK)
        self.assertEqual(service.validated_rulesets, [[RULE_TWO]])
        self.assertTrue(self.rules_path.read_text(encoding="utf-8").startswith("# " + RULE_ONE))

    def test_reload_failure_restores_exact_snapshot(self):
        original = self.rules_path.read_bytes()
        service = FakeRulesService(
            self.repository,
            reload_results=[(500, {"reloaded": False}), (200, {"reloaded": True})],
        )
        result = service.update_rule_by_sid(100001, RULE_ONE_UPDATED)
        self.assertEqual(result.state, ServiceState.RELOAD_FAILED)
        self.assertTrue(result.payload["rolled_back"])
        self.assertTrue(result.payload["rollback_reload_succeeded"])
        self.assertEqual(self.rules_path.read_bytes(), original)

    def test_duplicate_sid_is_rejected_before_validation(self):
        service = FakeRulesService(self.repository)
        result = service.create_rule_from_raw(RULE_ONE)
        self.assertEqual(result.state, ServiceState.CONFLICT)
        self.assertEqual(result.payload["sid"], 100001)
        self.assertTrue({"path", "rules_dir", "rules_file", "snort_agent_url"}.isdisjoint(result.payload))
        self.assertEqual(service.validated_rulesets, [])

    def test_detail_exposes_rule_data_without_internal_metadata(self):
        service = FakeRulesService(self.repository)
        result = service.get_rule_detail_by_sid(100001)
        self.assertEqual(result.state, ServiceState.OK)
        self.assertTrue({"path", "rules_dir", "rules_file", "snort_agent_url"}.isdisjoint(result.payload))


if __name__ == "__main__":
    unittest.main()
