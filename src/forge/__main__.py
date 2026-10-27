"""Inspection only: this CLI cannot execute mutations."""
import argparse
import json
import sys

from .manager import Manager
from .safety import SafetyError


def main(argv=None):
    parser = argparse.ArgumentParser(description="Forge local worktree dry-run inspector")
    parser.add_argument("--registry", required=True)
    parser.add_argument("--allowed-root", action="append", required=True)
    parser.add_argument("--worktree-root", required=True)
    parser.add_argument("--dry-run", action="store_true", required=True)
    sub = parser.add_subparsers(dest="operation", required=True)
    approve = sub.add_parser("approve")
    approve.add_argument("repository_id")
    approve.add_argument("path")
    for name in ("create", "cleanup"):
        command = sub.add_parser(name)
        command.add_argument("repository_id")
        command.add_argument("task_id")
    args = parser.parse_args(argv)
    try:
        manager = Manager(args.registry, args.allowed_root, args.worktree_root)
        method = getattr(manager, args.operation)
        outcome = method(args.repository_id, args.path if args.operation == "approve" else args.task_id, dry_run=True)
    except (SafetyError, UnicodeError) as exc:
        print(json.dumps({"ok": False, "operation": args.operation, "dry_run": True,
                          "error": {"code": "safety_refusal", "message": str(exc)}}))
        return 1
    print(json.dumps(outcome, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
