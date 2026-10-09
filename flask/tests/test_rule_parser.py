import sys
import unittest
from pathlib import Path


FLASK_SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(FLASK_SRC))

from parser import RuleParser


class RuleParserTests(unittest.TestCase):
    def test_summary_exposes_extended_contract_and_legacy_endpoints(self):
        rule = (
            'alert icmp 10.10.0.3 any -> 10.10.0.2 none '
            '(msg:"ICMP TEST"; classtype:icmp-event; sid:100002; rev:2;)'
        )
        summary = RuleParser.parse_summary(rule)

        self.assertEqual(summary.sid, 100002)
        self.assertEqual(summary.rev, 2)
        self.assertEqual(summary.action, "alert")
        self.assertEqual(summary.protocol, "icmp")
        self.assertEqual(summary.src, "10.10.0.3:any")
        self.assertEqual(summary.dst, "10.10.0.2:none")
        self.assertEqual(summary.src_ip, "10.10.0.3")
        self.assertEqual(summary.src_port, "any")
        self.assertEqual(summary.direction, "->")
        self.assertEqual(summary.dst_ip, "10.10.0.2")
        self.assertEqual(summary.dst_port, "none")
        self.assertEqual(summary.msg, "ICMP TEST")
        self.assertEqual(summary.classtype, "icmp-event")

    def test_quoted_semicolon_is_not_an_option_separator(self):
        options = RuleParser.parse_options('msg:"alpha; beta"; sid:1; rev:1;')
        self.assertEqual(options["msg"], "alpha; beta")
        self.assertEqual(options["sid"], "1")

    def test_repeated_options_are_preserved_as_lists(self):
        options = RuleParser.parse_options(
            'content:"first"; content:"second"; '
            'reference:cve,2026-0001; reference:url,example.test;'
        )
        self.assertEqual(options["content"], ["first", "second"])
        self.assertEqual(
            options["reference"],
            ["cve,2026-0001", "url,example.test"],
        )

    def test_option_without_value_is_boolean_true(self):
        options = RuleParser.parse_options('content:"case insensitive"; nocase; sid:1;')
        self.assertIs(options["nocase"], True)

    def test_detail_contains_every_option_and_normalizes_sid_revision(self):
        rule = (
            'alert tcp any any <> any 443 '
            '(msg:"detail"; flow:established; content:"one"; content:"two"; '
            'nocase; classtype:misc-activity; sid:1234; rev:7;)'
        )
        detail = RuleParser.parse_detail(rule, line_number=8)

        self.assertEqual(detail.status, "parsed")
        self.assertEqual(detail.sid, 1234)
        self.assertEqual(detail.rev, 7)
        self.assertEqual(detail.classtype, "misc-activity")
        self.assertEqual(detail.header.direction, "<>")
        self.assertEqual(detail.options["content"], ["one", "two"])
        self.assertEqual(detail.options["flow"], "established")
        self.assertIs(detail.options["nocase"], True)
        self.assertEqual(detail.options["sid"], 1234)
        self.assertEqual(detail.options["rev"], 7)

    def test_colon_inside_quoted_value_is_preserved(self):
        options = RuleParser.parse_options('msg:"source: destination"; sid:1;')
        self.assertEqual(options["msg"], "source: destination")

    def test_malformed_rule_returns_empty_summary_fields(self):
        summary = RuleParser.parse_summary("not a complete rule")
        self.assertIsNone(summary.sid)
        self.assertIsNone(summary.rev)
        self.assertIsNone(summary.direction)
        self.assertIsNone(summary.classtype)

    def test_invalid_sid_marks_detail_partial(self):
        detail = RuleParser.parse_detail(
            'alert icmp any any -> any any (msg:"bad sid"; sid:not-a-number; rev:1;)',
            line_number=1,
        )
        self.assertEqual(detail.status, "partial")
        self.assertIsNone(detail.sid)
        self.assertIn("sid is not a valid integer", detail.warnings)


if __name__ == "__main__":
    unittest.main()
