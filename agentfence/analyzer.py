"""Command parser, risk scorer, and dry-run filesystem blast-radius simulator."""

from __future__ import annotations

import glob
import re
import shlex
from pathlib import Path
from typing import Any, Dict, List, Optional

from .policy import load_policy


def _split_tokens(cmd: str) -> List[str]:
    try:
        return shlex.split(cmd, posix=True)
    except ValueError:
        return cmd.split()


def _simulate_blast_radius(tokens: List[str], cwd: Path, protected_paths: List[str]) -> Dict[str, Any]:
    affected_files: List[str] = []
    protected_hits: List[str] = []

    cwd_resolved = cwd.resolve()
    candidates = [t for t in tokens[1:] if not t.startswith("-") and t not in ("&&", "||", "|", ";")]
    for arg in candidates:
        clean = arg.strip("\"'")
        if not clean:
            continue
        # Check protected path prefixes
        for prot in protected_paths:
            norm_arg = clean.replace("\\", "/")
            norm_prot = prot.replace("\\", "/").rstrip("/")
            if norm_arg == norm_prot or norm_arg.startswith(norm_prot + "/") or f"/{norm_prot}" in norm_arg:
                protected_hits.append(clean)

        # Never walk root, home, or arbitrary absolute host paths during dry-run simulation
        if clean.startswith(("/", "~", "\\")) or (len(clean) >= 2 and clean[1] == ":"):
            continue

        # Expand globs or relative paths strictly inside cwd (bounded)
        if any(ch in clean for ch in ("*", "?", "[")):
            matches = glob.glob(str(cwd_resolved / clean), recursive=False)
            for m in matches[:50]:
                try:
                    rel = str(Path(m).resolve().relative_to(cwd_resolved)).replace("\\", "/")
                except ValueError:
                    continue
                affected_files.append(rel)
        else:
            p = (cwd_resolved / clean).resolve()
            try:
                p.relative_to(cwd_resolved)
            except ValueError:
                continue
            if p.exists():
                if p.is_dir():
                    for child in p.iterdir():
                        if len(affected_files) >= 50:
                            break
                        if child.is_file():
                            affected_files.append(str(child.relative_to(cwd_resolved)).replace("\\", "/"))
                else:
                    affected_files.append(str(p.relative_to(cwd_resolved)).replace("\\", "/"))

    return {
        "estimated_files": sorted(set(affected_files)),
        "estimated_count": len(set(affected_files)),
        "protected_hits": sorted(set(protected_hits)),
    }


def check_command(
    command: str,
    policy_path: Optional[str] = None,
    cwd: str = ".",
) -> Dict[str, Any]:
    policy = load_policy(policy_path)
    cwd_path = Path(cwd).resolve()
    tokens = _split_tokens(command)

    matched_rules: List[Dict[str, str]] = []
    verdict = "allow"
    risk_score = 5

    for rule in policy.get("deny_patterns", []):
        if re.search(rule["pattern"], command, re.IGNORECASE):
            matched_rules.append({"id": rule["id"], "level": "deny", "category": rule["category"], "reason": rule["reason"]})
            verdict = "deny"
            risk_score = max(risk_score, 90)

    if verdict != "deny":
        for rule in policy.get("confirm_patterns", []):
            if re.search(rule["pattern"], command, re.IGNORECASE):
                matched_rules.append({"id": rule["id"], "level": "confirm", "category": rule["category"], "reason": rule["reason"]})
                verdict = "confirm"
                risk_score = max(risk_score, 55)

    blast = _simulate_blast_radius(tokens, cwd_path, policy.get("protected_paths", []))
    if blast["protected_hits"]:
        matched_rules.append(
            {
                "id": "protected-path-access",
                "level": "deny",
                "category": "filesystem",
                "reason": f"Touches protected path(s): {', '.join(blast['protected_hits'])}",
            }
        )
        verdict = "deny"
        risk_score = 95
    elif blast["estimated_count"] >= 10 and verdict == "allow":
        verdict = "confirm"
        risk_score = max(risk_score, 60)

    return {
        "command": command,
        "verdict": verdict,
        "risk_score": risk_score,
        "matched_rules": matched_rules,
        "blast_radius": blast,
    }
