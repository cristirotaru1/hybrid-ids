import os
from dataclasses import dataclass
from pathlib import Path


class ConfigError(ValueError):
    """Raised when required application configuration is missing or invalid."""


def _required(environment: dict[str, str], name: str) -> str:
    value = environment.get(name, "").strip()
    if not value:
        raise ConfigError(f"Required environment variable {name} is not set")
    return value


def _port(environment: dict[str, str], name: str, default: int) -> int:
    raw = environment.get(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if not 1 <= value <= 65535:
        raise ConfigError(f"{name} must be between 1 and 65535")
    return value


def _boolean(environment: dict[str, str], name: str, default: bool = False) -> bool:
    raw = environment.get(name)
    if raw is None:
        return default
    value = raw.split("#", 1)[0].strip().lower()
    if value in {"true", "1", "yes", "on"}:
        return True
    if value in {"false", "0", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be true or false")


@dataclass(frozen=True)
class AppConfig:
    rules_dir: Path | None
    rules_file: str | None
    snort_agent_url: str | None
    floodlight_host: str | None
    floodlight_port: int
    switch_dpid: str | None
    react_dry_run: bool
    reaction_db_path: Path
    switch_name: str
    switch_cidr: str

    @classmethod
    def from_env(
        cls,
        environment: dict[str, str] | None = None,
        *,
        require_rules: bool = True,
    ) -> "AppConfig":
        env = os.environ if environment is None else environment
        if require_rules:
            rules_dir = Path(_required(env, "RULES_DIR"))
            rules_file = _required(env, "RULES_FILE")
            snort_agent_url = _required(env, "SNORT_AGENT_URL").rstrip("/")
        else:
            rules_dir_raw = env.get("RULES_DIR", "").strip()
            rules_dir = Path(rules_dir_raw) if rules_dir_raw else None
            rules_file = env.get("RULES_FILE", "").strip() or None
            snort_raw = env.get("SNORT_AGENT_URL", "").strip()
            snort_agent_url = snort_raw.rstrip("/") or None

        return cls(
            rules_dir=rules_dir,
            rules_file=rules_file,
            snort_agent_url=snort_agent_url,
            floodlight_host=env.get("FLOODLIGHT_HOST", "").strip() or None,
            floodlight_port=_port(env, "FLOODLIGHT_PORT", 8080),
            switch_dpid=env.get("SWITCH_DPID", "").strip() or None,
            react_dry_run=_boolean(env, "REACT_DRY_RUN", default=True),
            reaction_db_path=Path(env.get("REACTION_DB_PATH", "/var/lib/reaction/reaction.db")),
            switch_name=env.get("SWITCH_NAME", "lab-switch").strip() or "lab-switch",
            switch_cidr=env.get("SWITCH_CIDR", "10.10.0.0/24").strip(),
        )

    def require_floodlight(self) -> None:
        missing = []
        if not self.floodlight_host:
            missing.append("FLOODLIGHT_HOST")
        if not self.switch_dpid:
            missing.append("SWITCH_DPID")
        if missing:
            raise ConfigError(f"Required Floodlight configuration is missing: {', '.join(missing)}")
