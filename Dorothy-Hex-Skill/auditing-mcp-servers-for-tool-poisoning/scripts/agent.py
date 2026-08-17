#!/usr/bin/env python3
# For authorized MCP server auditing only. Do not scan servers you do not control
# or lack written permission to assess.
"""MCP tool-poisoning audit agent.

Two modes:
  static  -- run Invariant Labs mcp-scan over an MCP config and parse results,
             plus a local heuristic scan of tool descriptions in the config.
  enum    -- launch a stdio MCP server, enumerate tools, and heuristically flag
             poisoned descriptions (hidden instructions, smuggled unicode).

Examples:
  python agent.py static --config ~/.cursor/mcp.json
  python agent.py enum --command node --args ./suspect-mcp-server.js
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

# Heuristics for instructions aimed at the assistant inside a tool description.
POISON_PATTERNS = [
    r"do not (tell|inform|mention to) the user",
    r"ignore (previous|prior|all) instructions",
    r"<important>|<system>|\[system\]",
    r"read .*(\.ssh|id_rsa|\.env|credentials|passwd)",
    r"(send|exfiltrate|post) .* to https?://",
    r"before (using|calling) (this|any) tool,? (you must|always)",
    r"call (the )?\w+ tool (first|before)",
]
SMUGGLE = re.compile(r"[​-‏‪-‮⁠-⁯\U000e0000-\U000e007f]")


def heuristic_flags(description: str):
    flags = []
    low = (description or "").lower()
    for pat in POISON_PATTERNS:
        if re.search(pat, low):
            flags.append(f"pattern:{pat}")
    if SMUGGLE.search(description or ""):
        flags.append("unicode-smuggling")
    if len(description or "") > 1500:
        flags.append("oversized-description")
    return flags


def run_static(args):
    findings = {"ts": datetime.now(timezone.utc).isoformat(),
                "config": args.config, "atlas": "AML.T0010", "scanner": None,
                "heuristic": []}

    # 1. Invoke mcp-scan if available
    runner = shutil.which("uvx") or shutil.which("mcp-scan")
    if runner:
        cmd = ([runner, "mcp-scan@latest", "--json", args.config]
               if "uvx" in runner else [runner, "--json", args.config])
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
            try:
                findings["scanner"] = json.loads(res.stdout)
            except json.JSONDecodeError:
                findings["scanner"] = {"raw": res.stdout[:4000], "stderr": res.stderr[:1000]}
        except subprocess.TimeoutExpired:
            findings["scanner"] = {"error": "mcp-scan timed out"}
    else:
        findings["scanner"] = {"error": "uvx/mcp-scan not found; install uv: "
                                        "curl -LsSf https://astral.sh/uv/install.sh | sh"}

    # 2. Local heuristic scan of any descriptions embedded in the config
    try:
        with open(args.config, encoding="utf-8") as fh:
            cfg = json.load(fh)
        for desc in _walk_descriptions(cfg):
            f = heuristic_flags(desc)
            if f:
                findings["heuristic"].append({"flags": f, "snippet": desc[:200]})
    except (OSError, json.JSONDecodeError) as exc:
        findings["heuristic"].append({"error": str(exc)})

    print(json.dumps(findings, indent=2))
    return findings


def _walk_descriptions(obj):
    """Yield any 'description' string values found anywhere in a nested config."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "description" and isinstance(v, str):
                yield v
            else:
                yield from _walk_descriptions(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_descriptions(item)


def run_enum(args):
    try:
        import asyncio
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
    except ImportError:
        print("Install: pip install mcp", file=sys.stderr)
        sys.exit(1)

    async def _enum():
        params = StdioServerParameters(command=args.command, args=args.args or [])
        out = {"ts": datetime.now(timezone.utc).isoformat(),
               "server": f"{args.command} {' '.join(args.args or [])}",
               "atlas": "AML.T0010", "tools": []}
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()
                tools = await s.list_tools()
                for t in tools.tools:
                    flags = heuristic_flags(t.description or "")
                    out["tools"].append({
                        "name": t.name,
                        "desc_len": len(t.description or ""),
                        "flags": flags,
                        "verdict": "POISONED?" if flags else "clean",
                    })
        print(json.dumps(out, indent=2))
        return out

    try:
        asyncio.run(_enum())
    except Exception as exc:  # connection/protocol errors
        print(f"[!] MCP enumeration failed: {exc}", file=sys.stderr)
        sys.exit(2)


def main():
    ap = argparse.ArgumentParser(description="MCP tool-poisoning audit agent")
    sub = ap.add_subparsers(dest="mode", required=True)

    ps = sub.add_parser("static", help="Run mcp-scan + heuristic scan on a config")
    ps.add_argument("--config", required=True, help="Path to MCP config JSON")

    pe = sub.add_parser("enum", help="Enumerate tools from a stdio MCP server")
    pe.add_argument("--command", required=True, help="Server launch command, e.g. node")
    pe.add_argument("--args", nargs="*", help="Arguments to the server command")

    args = ap.parse_args()
    if args.mode == "static":
        run_static(args)
    else:
        run_enum(args)


if __name__ == "__main__":
    main()
