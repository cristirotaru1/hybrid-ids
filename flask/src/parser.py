import re
from typing import Any
from models import RuleHeader, RuleSummary, RuleDetail


class RuleParser:
    @staticmethod
    def split_rule(rule_line: str):
        start = rule_line.find("(")
        end = rule_line.rfind(")")

        if start == -1 or end == -1 or end < start:
            return None, None

        header_text = rule_line[:start].strip()
        options_text = rule_line[start + 1:end].strip()
        return header_text, options_text

    @staticmethod
    def parse_header(header_text: str) -> RuleHeader | None:
        parts = re.split(r"\s+(->|<>)\s+", header_text, maxsplit=1)

        if len(parts) != 3:
            return None

        left, direction, right = parts
        left_tokens = left.split()
        right_tokens = right.split()

        if len(left_tokens) != 4 or len(right_tokens) != 2:
            return None

        return RuleHeader(
            action=left_tokens[0],
            protocol=left_tokens[1],
            src_ip=left_tokens[2],
            src_port=left_tokens[3],
            direction=direction,
            dst_ip=right_tokens[0],
            dst_port=right_tokens[1],
        )

    @staticmethod
    def split_options(options_text: str) -> list[str]:
        """Split options on semicolons while preserving quoted semicolons."""
        tokens = []
        current = []
        in_quotes = False
        escaped = False

        for char in options_text:
            if escaped:
                current.append(char)
                escaped = False
                continue

            if char == "\\" and in_quotes:
                current.append(char)
                escaped = True
                continue

            if char == '"':
                in_quotes = not in_quotes
                current.append(char)
                continue

            if char == ";" and not in_quotes:
                token = "".join(current).strip()
                if token:
                    tokens.append(token)
                current = []
                continue

            current.append(char)

        token = "".join(current).strip()
        if token:
            tokens.append(token)
        return tokens

    @staticmethod
    def parse_options(options_text: str) -> dict[str, Any]:
        """Parse all options and retain repeated options as ordered lists."""
        options: dict[str, Any] = {}

        for token in RuleParser.split_options(options_text):
            name, separator, raw_value = token.partition(":")
            name = name.strip()
            if not name:
                continue

            value: Any
            if not separator:
                value = True
            else:
                value = raw_value.strip()
                if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
                    value = value[1:-1]

            if name not in options:
                options[name] = value
            elif isinstance(options[name], list):
                options[name].append(value)
            else:
                options[name] = [options[name], value]

        return options

    @staticmethod
    def extract_option(options_text: str, option_name: str):
        value = RuleParser.parse_options(options_text).get(option_name)
        if isinstance(value, list):
            return value[0]
        return value

    @staticmethod
    def parse_summary(rule_line: str) -> RuleSummary:
        header_text, options_text = RuleParser.split_rule(rule_line)

        if not header_text or not options_text:
            return RuleSummary(
                sid=None,
                rev=None,
                action=None,
                protocol=None,
                src=None,
                dst=None,
                src_ip=None,
                src_port=None,
                direction=None,
                dst_ip=None,
                dst_port=None,
                msg=None,
                classtype=None,
            )

        header = RuleParser.parse_header(header_text)
        options = RuleParser.parse_options(options_text)
        sid = options.get("sid")
        rev = options.get("rev")
        msg = options.get("msg")
        classtype = options.get("classtype")

        sid = RuleParser._int_or_original(sid)
        rev = RuleParser._int_or_original(rev)

        if header is None:
            return RuleSummary(
                sid=sid,
                rev=rev,
                action=None,
                protocol=None,
                src=None,
                dst=None,
                src_ip=None,
                src_port=None,
                direction=None,
                dst_ip=None,
                dst_port=None,
                msg=msg,
                classtype=classtype,
            )

        return RuleSummary(
            sid=sid,
            rev=rev,
            action=header.action,
            protocol=header.protocol,
            src=header.src,
            dst=header.dst,
            src_ip=header.src_ip,
            src_port=header.src_port,
            direction=header.direction,
            dst_ip=header.dst_ip,
            dst_port=header.dst_port,
            msg=msg,
            classtype=classtype,
        )

    @staticmethod
    def parse_detail(rule_line: str, line_number: int) -> RuleDetail:
        header_text, options_text = RuleParser.split_rule(rule_line)
        warnings = []

        if not header_text or not options_text:
            return RuleDetail(
                sid=None,
                rev=None,
                msg=None,
                classtype=None,
                raw=rule_line,
                line_number=line_number,
                header=None,
                options={},
                warnings=["Rule does not contain a valid header/options structure"],
                status="invalid",
            )

        header = RuleParser.parse_header(header_text)
        if header is None:
            warnings.append("Header could not be parsed")

        options = RuleParser.parse_options(options_text)
        sid = options.get("sid")
        rev = options.get("rev")
        msg = options.get("msg")
        classtype = options.get("classtype")

        if sid is not None:
            try:
                sid = int(str(sid).strip())
            except ValueError:
                warnings.append("sid is not a valid integer")
                sid = None

        if rev is not None:
            try:
                rev = int(str(rev).strip())
            except ValueError:
                warnings.append("rev is not a valid integer")
                rev = None

        options["sid"] = sid
        options["rev"] = rev

        status = "parsed" if not warnings else "partial"

        return RuleDetail(
            sid=sid,
            rev=rev,
            msg=msg,
            classtype=classtype,
            raw=rule_line,
            line_number=line_number,
            header=header,
            options=options,
            warnings=warnings,
            status=status,
        )

    @staticmethod
    def _int_or_original(value):
        if value is None or isinstance(value, list):
            return value
        try:
            return int(str(value).strip())
        except ValueError:
            return value
