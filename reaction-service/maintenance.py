import argparse
import json
import os

try:
    from reaction_common import ReactionStore
except ModuleNotFoundError as error:
    if error.name != "ids":
        raise
    # The Docker image copies the shared package directly into /app.
    from reaction_common import ReactionStore


def main() -> None:
    parser = argparse.ArgumentParser(description="Reaction database maintenance")
    subcommands = parser.add_subparsers(dest="command", required=True)
    cleanup = subcommands.add_parser("cleanup")
    cleanup.add_argument("--pending-retention-days", type=int, default=30)
    cleanup.add_argument("--audit-retention-days", type=int, default=90)
    migrate = subcommands.add_parser("import-json")
    migrate.add_argument("--pending", default="/var/log/reaction/pending_blocks.json")
    migrate.add_argument("--audit", default="/var/log/reaction/audit.jsonl")
    args = parser.parse_args()
    store = ReactionStore(os.environ.get("REACTION_DB_PATH", "/var/lib/reaction/reaction.db"))
    if args.command == "cleanup":
        result = store.cleanup(args.pending_retention_days, args.audit_retention_days)
    else:
        result = store.import_legacy(args.pending, args.audit)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
