"""CLI entrypoint for agentfence."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from typing import List, Optional

from . import __version__
from .analyzer import check_command
from .ledger import append_ledger, verify_ledger


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agentfence",
        description="Dry-run capability firewall, blast-radius simulator, and hash-chained audit ledger for AI agents.",
    )
    p.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    pc = sub.add_parser("check", help="Dry-run a command against policy and simulate blast radius.")
    pc.add_argument("cmd", help="Command string to evaluate")
    pc.add_argument("--policy", help="Path to fence.toml or policy.json")
    pc.add_argument("--cwd", default=".", help="Working directory for blast-radius simulation")
    pc.add_argument("--json", action="store_true", help="Emit JSON report")

    pr = sub.add_parser("run", help="Enforce policy, run command if allowed, and log to SHA-256 ledger.")
    pr.add_argument("--policy", help="Path to fence.toml or policy.json")
    pr.add_argument("--ledger", default=".agentfence/audit.jsonl", help="Audit ledger JSONL path")
    pr.add_argument("--approve", action="store_true", help="Approve `confirm`-level commands")
    pr.add_argument("--cwd", default=".", help="Working directory")
    pr.add_argument("cmd", nargs=argparse.REMAINDER, help="Command after --")

    pv = sub.add_parser("verify-ledger", help="Verify SHA-256 hash chain integrity of an audit ledger.")
    pv.add_argument("path", default=".agentfence/audit.jsonl", nargs="?", help="Ledger JSONL path")
    pv.add_argument("--json", action="store_true", help="Emit JSON report")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "check":
        res = check_command(args.cmd, policy_path=args.policy, cwd=args.cwd)
        if args.json:
            sys.stdout.write(json.dumps(res, ensure_ascii=False, indent=2) + "\n")
        else:
            sys.stdout.write(
                f"Verdict: {res['verdict'].upper()} (risk={res['risk_score']}/100, files={res['blast_radius']['estimated_count']})\n"
            )
            for r in res["matched_rules"]:
                sys.stdout.write(f"  [{r['level'].upper()}] {r['id']}: {r['reason']}\n")
        return {"allow": 0, "deny": 1, "confirm": 2}[res["verdict"]]

    if args.command == "run":
        raw_cmd = args.cmd[1:] if args.cmd and args.cmd[0] == "--" else args.cmd
        if not raw_cmd:
            sys.stderr.write("Error: `agentfence run` requires `-- <command>`.\n")
            return 2
        cmd_str = " ".join(shlex.quote(x) for x in raw_cmd)
        res = check_command(cmd_str, policy_path=args.policy, cwd=args.cwd)
        if res["verdict"] == "deny" or (res["verdict"] == "confirm" and not args.approve):
            append_ledger(args.ledger, {"command": cmd_str, "verdict": res["verdict"], "executed": False, "exit_code": None})
            sys.stderr.write(f"agentfence blocked ({res['verdict']}): {cmd_str}\n")
            return 1 if res["verdict"] == "deny" else 2
        proc = subprocess.run(raw_cmd, cwd=args.cwd, check=False)
        append_ledger(args.ledger, {"command": cmd_str, "verdict": res["verdict"], "executed": True, "exit_code": proc.returncode})
        return proc.returncode

    if args.command == "verify-ledger":
        v = verify_ledger(args.path)
        if args.json:
            sys.stdout.write(json.dumps(v, ensure_ascii=False, indent=2) + "\n")
        else:
            sys.stdout.write(
                f"Ledger valid: {v['valid']} ({v.get('entries', 0)} entries)\n"
                if v["valid"]
                else f"Ledger INVALID: {v.get('error')}\n"
            )
        return 0 if v["valid"] else 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
