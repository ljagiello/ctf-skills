#!/usr/bin/env python3
# Defensive AI-security control. Deploy on agents you own/operate.
"""Agentic AI tool-invocation policy gate.

Implements deny-by-default tool allowlisting, per-tool JSON-schema argument
validation, an allow/require_approval/deny decision, an interactive human-in-the-loop
approval gate for high-impact tools, and a structured audit log for SIEM ingestion.

Examples:
  python agent.py --tool search_docs --args '{"query":"vpn policy"}'
  python agent.py --tool send_email --args '{"to":"a@example.com","subject":"x","body":"y"}'
  python agent.py --tool transfer_funds --args '{"amount":50}' --auto-approve
"""
import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone

try:
    from jsonschema import validate, ValidationError
except ImportError:
    print("Install: pip install jsonschema", file=sys.stderr)
    sys.exit(1)

# Impact tiers and approval requirements (deny-by-default: unknown tools rejected).
TOOL_POLICY = {
    "search_docs":   {"impact": "read",  "approval": False},
    "create_ticket": {"impact": "write", "approval": False},
    "send_email":    {"impact": "high",  "approval": True},
    "transfer_funds":{"impact": "high",  "approval": True},
    "run_shell":     {"impact": "high",  "approval": True},
}

# Per-tool argument allowlists.
TOOL_SCHEMAS = {
    "search_docs": {
        "type": "object",
        "properties": {"query": {"type": "string", "maxLength": 500}},
        "required": ["query"], "additionalProperties": False,
    },
    "create_ticket": {
        "type": "object",
        "properties": {"title": {"type": "string", "maxLength": 200},
                       "body": {"type": "string", "maxLength": 5000}},
        "required": ["title"], "additionalProperties": False,
    },
    "send_email": {
        "type": "object",
        "properties": {
            "to": {"type": "string", "pattern": r"^[^@\s]+@example\.com$"},
            "subject": {"type": "string", "maxLength": 200},
            "body": {"type": "string", "maxLength": 5000},
        },
        "required": ["to", "subject", "body"], "additionalProperties": False,
    },
    "transfer_funds": {
        "type": "object",
        "properties": {"amount": {"type": "number", "minimum": 0, "maximum": 1000},
                       "account": {"type": "string"}},
        "required": ["amount"], "additionalProperties": False,
    },
    "run_shell": {
        "type": "object",
        "properties": {"cmd": {"type": "string", "enum": ["ls", "whoami", "df -h"]}},
        "required": ["cmd"], "additionalProperties": False,
    },
}


def validate_args(tool, args):
    schema = TOOL_SCHEMAS.get(tool)
    if schema is None:
        return False, "no schema (deny-by-default)"
    try:
        validate(instance=args, schema=schema)
        return True, "ok"
    except ValidationError as exc:
        return False, f"schema: {exc.message}"


def authorize(tool, args, actor):
    policy = TOOL_POLICY.get(tool)
    if policy is None:
        return _event("deny", tool, args, actor, "tool not in allowlist")
    ok, why = validate_args(tool, args)
    if not ok:
        return _event("deny", tool, args, actor, why)
    if policy["approval"]:
        return _event("require_approval", tool, args, actor,
                      f"high-impact ({policy['impact']})")
    return _event("allow", tool, args, actor, "allowlisted")


def _event(decision, tool, args, actor, reason):
    return {
        "ts": datetime.now(timezone.utc).isoformat(), "actor": actor, "tool": tool,
        "args_sha256": hashlib.sha256(
            json.dumps(args, sort_keys=True).encode()).hexdigest(),
        "decision": decision, "reason": reason, "atlas": "AML.T0053",
    }


def hitl_prompt(event, auto_approve):
    """Fail-closed human-in-the-loop gate."""
    if auto_approve:
        return True
    if not sys.stdin.isatty():
        return False  # no interactive approver -> deny
    ans = input(f"APPROVAL: call {event['tool']} "
                f"(args {event['args_sha256'][:12]})? [y/N] ").strip().lower()
    return ans == "y"


def main():
    ap = argparse.ArgumentParser(description="Agentic AI tool-invocation policy gate")
    ap.add_argument("--tool", required=True, help="Tool the agent wants to call")
    ap.add_argument("--args", default="{}", help="JSON tool arguments")
    ap.add_argument("--actor", default="agent-session", help="Acting user/session id")
    ap.add_argument("--auto-approve", action="store_true",
                    help="Auto-approve HITL (testing only)")
    ap.add_argument("--audit-log", help="Append audit events to this JSONL file")
    args = ap.parse_args()

    try:
        tool_args = json.loads(args.args)
        if not isinstance(tool_args, dict):
            raise ValueError("args must be a JSON object")
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"[!] Invalid --args: {exc}", file=sys.stderr)
        sys.exit(2)

    event = authorize(args.tool, tool_args, args.actor)

    if event["decision"] == "require_approval":
        approved = hitl_prompt(event, args.auto_approve)
        event["decision"] = "allow" if approved else "deny"
        event["reason"] += "; approved" if approved else "; not approved (fail-closed)"

    print(json.dumps(event, indent=2))
    if args.audit_log:
        with open(args.audit_log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event) + "\n")

    sys.exit(0 if event["decision"] == "allow" else 1)


if __name__ == "__main__":
    main()
