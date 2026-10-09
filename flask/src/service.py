import requests

from dataclasses import asdict
from models import ServiceResult, ServiceState
from parser import RuleParser
from repository import RulesRepository


class RulesService:
    def __init__(self, repository: RulesRepository, snort_agent_url: str):
        self.repository = repository
        self.snort_agent_url = snort_agent_url.rstrip("/")

    def list_rule_summaries(self) -> list[dict]:
        lines = self.repository.read_active_lines()
        summaries = []

        for _, raw_line in lines:
            summaries.append(RuleParser.parse_summary(raw_line))

        return [asdict(summary) for summary in summaries]

    def get_rule_detail_by_sid(self, sid: int):
        lines = self.repository.read_active_lines()
        matches = []

        for line_number, raw_line in lines:
            detail = RuleParser.parse_detail(raw_line, line_number)
            if detail.sid == sid:
                matches.append(detail)

        if not matches:
            return ServiceResult(
                ServiceState.NOT_FOUND,
                {"error": f"Rule with SID {sid} not found"},
            )

        if len(matches) > 1:
            return ServiceResult(ServiceState.CONFLICT, {
                "error": f"Duplicate active SID detected: {sid}",
                "sid": sid,
                "match_count": len(matches),
            })

        return ServiceResult(ServiceState.OK, asdict(matches[0]))

    def create_rule_from_raw(self, raw_rule: str):
        raw_rule = self._normalize_raw_rule(raw_rule)
        if raw_rule is None:
            return ServiceResult(ServiceState.BAD_REQUEST, {"error": "Rule text cannot be empty"})

        detail, parse_error = self._parse_candidate_rule(raw_rule)
        if parse_error is not None:
            return ServiceResult(ServiceState.BAD_REQUEST, parse_error)

        with self.repository.mutation_lock():
            conflict_error = self._build_duplicate_sid_error(detail.sid)
            if conflict_error is not None:
                return ServiceResult(ServiceState.CONFLICT, conflict_error)

            active_rules = [rule for _, rule in self.repository.read_active_lines()]
            validation_result = self._validate_ruleset(active_rules + [raw_rule])
            if validation_result.state is not ServiceState.OK:
                return validation_result

            snapshot = self.repository.snapshot()
            line_number = self.repository.append_rule(raw_rule)

            reload_result = self._reload_after_write(
                sid=detail.sid,
                line_number=line_number
            )
            if reload_result.state is not ServiceState.OK:
                return self._rollback_after_reload_failure(snapshot, reload_result)

        return ServiceResult(ServiceState.CREATED, {
            "message": "Rule created successfully",
            "sid": detail.sid,
            "line_number": line_number,
        })

    def update_rule_by_sid(self, sid: int, raw_rule: str):
        raw_rule = self._normalize_raw_rule(raw_rule)
        if raw_rule is None:
            return ServiceResult(ServiceState.BAD_REQUEST, {"error": "Rule text cannot be empty"})

        detail, parse_error = self._parse_candidate_rule(raw_rule)
        if parse_error is not None:
            return ServiceResult(ServiceState.BAD_REQUEST, parse_error)

        if detail.sid != sid:
            return ServiceResult(ServiceState.BAD_REQUEST, {
                "error": "SID in rule body must match the current SID",
                "sid": sid,
                "candidate_sid": detail.sid,
            })

        with self.repository.mutation_lock():
            current_result = self.get_rule_detail_by_sid(sid)
            if current_result.state is not ServiceState.OK:
                return current_result

            line_number = current_result.payload["line_number"]
            prospective_rules = [
                raw_rule if current_line == line_number else active_raw
                for current_line, active_raw in self.repository.read_active_lines()
            ]
            validation_result = self._validate_ruleset(prospective_rules)
            if validation_result.state is not ServiceState.OK:
                return validation_result

            snapshot = self.repository.snapshot()
            self.repository.replace_line(line_number, raw_rule)

            reload_result = self._reload_after_write(
                sid=sid,
                line_number=line_number,
            )
            if reload_result.state is not ServiceState.OK:
                return self._rollback_after_reload_failure(snapshot, reload_result)

        return ServiceResult(ServiceState.OK, {
            "message": "Rule updated successfully",
            "sid": sid,
            "line_number": line_number,
        })

    def disable_rule_by_sid(self, sid: int):
        with self.repository.mutation_lock():
            lines = self.repository.read_active_lines()
            matches = []

            for line_number, raw_line in lines:
                detail = RuleParser.parse_detail(raw_line, line_number)
                if detail.sid == sid:
                    matches.append(detail)

            if not matches:
                return ServiceResult(
                    ServiceState.NOT_FOUND,
                    {"error": f"Active rule with SID {sid} not found"},
                )

            if len(matches) > 1:
                return ServiceResult(ServiceState.CONFLICT, {
                    "error": f"Duplicate active SID detected: {sid}",
                    "sid": sid,
                    "match_count": len(matches),
                })

            match = matches[0]
            prospective_rules = [
                active_raw for line_number, active_raw in lines
                if line_number != match.line_number
            ]
            validation_result = self._validate_ruleset(prospective_rules)
            if validation_result.state is not ServiceState.OK:
                return validation_result

            snapshot = self.repository.snapshot()
            self.repository.comment_line(match.line_number)

            reload_result = self._reload_after_write(
                sid=sid,
                line_number=match.line_number
            )
            if reload_result.state is not ServiceState.OK:
                return self._rollback_after_reload_failure(snapshot, reload_result)

        return ServiceResult(ServiceState.OK, {
            "message": "Rule disabled successfully",
            "sid": sid,
            "line_number": match.line_number,
        })


    def validate_rule_with_snort(self, raw_rule: str):
        return self._post_to_snort_agent("/validate-rule", {"raw": raw_rule}, 20)

    def validate_rules_with_snort(self, rules: list[str]):
        return self._post_to_snort_agent("/validate-ruleset", {"rules": rules}, 20)

    def reload_snort(self):
        return self._post_to_snort_agent("/reload", None, 10)

    def _normalize_raw_rule(self, raw_rule: str):
        normalized = (raw_rule or "").strip()
        return normalized or None

    def _parse_candidate_rule(self, raw_rule: str):
        detail = RuleParser.parse_detail(raw_rule, line_number=0)

        if detail.status != "parsed":
            return None, {
                "error": "Rule parsing failed",
                "status": detail.status,
                "warnings": detail.warnings,
                "details": "Rule must parse cleanly before validation",
            }

        if detail.sid is None:
            return None, {
                "error": "Rule parsing failed",
                "status": detail.status,
                "warnings": detail.warnings,
                "details": "Rule does not contain a valid SID",
            }

        return detail, None

    def _build_duplicate_sid_error(self, sid: int):
        matches = self._find_active_sid_matches(sid)

        if not matches:
            return None

        return {
            "error": f"Active rule with SID {sid} already exists",
            "sid": sid,
            "match_count": len(matches),
        }

    def _find_active_sid_matches(self, sid: int):
        matches = []

        for line_number, active_raw in self.repository.read_active_lines():
            detail = RuleParser.parse_detail(active_raw, line_number)
            if detail.sid == sid:
                matches.append(detail)

        return matches

    def _validate_ruleset(self, rules: list[str]):
        try:
            status_code, payload = self.validate_rules_with_snort(rules)
        except requests.RequestException as exc:
            return ServiceResult(ServiceState.AGENT_ERROR, {
                "error": "Could not contact Snort agent for validation",
                "details": str(exc),
            })

        warnings = payload.get("warnings") or []
        if warnings:
            return ServiceResult(ServiceState.BAD_REQUEST, {
                "error": "Snort validation returned warnings",
                "warnings": warnings,
                "details": payload.get("details"),
            })

        if status_code != 200 or payload.get("valid") is not True:
            return ServiceResult(ServiceState.BAD_REQUEST, {
                "error": "Snort validation failed",
                "details": payload.get("details") or payload.get("error"),
            })

        return ServiceResult(ServiceState.OK)

    def _reload_after_write(self, sid: int, line_number: int):
        try:
            status_code, payload = self.reload_snort()
        except requests.RequestException as exc:
            return ServiceResult(ServiceState.RELOAD_FAILED, {
                "error": "Reloading file request failed",
                "sid": sid,
                "line_number": line_number,
                "details": str(exc),
            })

        if status_code != 200 or payload.get("reloaded") is not True:
            return ServiceResult(ServiceState.RELOAD_FAILED, {
                "error": "Reloading file request failed",
                "sid": sid,
                "line_number": line_number,
                "reload": payload,
            })

        return ServiceResult(ServiceState.OK)

    def _rollback_after_reload_failure(self, snapshot: bytes, reload_result: ServiceResult):
        self.repository.restore(snapshot)

        try:
            status_code, payload = self.reload_snort()
            rollback_reloaded = status_code == 200 and payload.get("reloaded") is True
            rollback_details = payload
        except requests.RequestException as exc:
            rollback_reloaded = False
            rollback_details = {"error": str(exc)}

        payload = dict(reload_result.payload)
        payload["rolled_back"] = True
        payload["rollback_reload_succeeded"] = rollback_reloaded
        payload["rollback_reload"] = rollback_details
        return ServiceResult(reload_result.state, payload)

    def _post_to_snort_agent(self, path: str, payload: dict | None, timeout: int):
        response = requests.post(
            f"{self.snort_agent_url}{path}",
            json=payload,
            timeout=timeout,
        )

        try:
            body = response.json()
        except ValueError:
            body = {
                "error": "Snort agent returned a non-JSON response",
                "status_code": response.status_code,
                "body": response.text.strip(),
            }

        return response.status_code, body
