"""Configure and start the reaction service."""

import logging
import os
import sys

from adapters.alert_tailer import AlertTailer
from adapters.alert_normalizer import AlertNormalizer
from adapters.email_notifier import EmailNotifier
from domain.response_policy import ResponsePolicy
from application.reaction_service import ReactionService
from reaction_common import ReactionStore


def _require(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        print(f"ERROR: required environment variable {name} is not set", file=sys.stderr)
        sys.exit(1)
    return val


def main():
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    smtp_host        = _require("SMTP_HOST")
    smtp_port        = int(os.environ.get("SMTP_PORT", "2525"))
    smtp_user        = _require("SMTP_USER")
    smtp_password    = _require("SMTP_PASSWORD")
    email_from       = _require("EMAIL_FROM")
    email_to         = _require("EMAIL_TO")
    confirm_base_url = _require("CONFIRM_BASE_URL")

    alert_file         = os.environ.get("ALERT_FILE", "/var/log/snort/alert_json.txt")
    database_path       = os.environ.get("REACTION_DB_PATH", "/var/lib/reaction/reaction.db")

    cooldown   = int(os.environ.get("COOLDOWN_SECONDS", "60"))
    token_ttl  = int(os.environ.get("TOKEN_TTL_SECONDS", "3600"))

    logging.getLogger(__name__).info(
        "Starting reaction service | smtp=%s:%d confirm_url=%s cooldown=%ds ttl=%ds",
        smtp_host, smtp_port, confirm_base_url, cooldown, token_ttl,
    )

    store = ReactionStore(database_path)
    controller_url = f"http://{_require('FLOODLIGHT_HOST')}:{int(os.environ.get('FLOODLIGHT_PORT', '8080'))}"
    store.register_switch(
        name=os.environ.get("SWITCH_NAME", "lab-switch"),
        controller_url=controller_url,
        dpid=_require("SWITCH_DPID"),
        cidr=os.environ.get("SWITCH_CIDR", "10.10.0.0/24"),
    )

    service = ReactionService(
        tailer        = AlertTailer(path=alert_file),
        normalizer    = AlertNormalizer(),
        policy        = ResponsePolicy(),
        store         = store,
        notifier      = EmailNotifier(
                            smtp_host=smtp_host,
                            smtp_port=smtp_port,
                            smtp_user=smtp_user,
                            smtp_password=smtp_password,
                            from_addr=email_from,
                            to_addr=email_to,
                            confirm_base_url=confirm_base_url,
                        ),
        token_ttl_seconds=token_ttl,
        cooldown_seconds=cooldown,
        email_attempts=int(os.environ.get("EMAIL_ATTEMPTS", "3")),
    )

    service.run()


if __name__ == "__main__":
    main()
