"""Policy loader (fence.toml / JSON) with safe defaults."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore

DEFAULT_POLICY: Dict[str, Any] = {
    "protected_paths": [".env", ".git", "migrations", "secrets", "/etc", "/usr", "C:\\Windows"],
    "deny_patterns": [
        {"id": "fs-root-rm", "category": "filesystem", "pattern": r"\brm\s+-[^\s]*(?:r[^\s]*f|f[^\s]*r)[^\s]*\s+(?:/\*?|~|\*|\$HOME)(?=\s|$)", "reason": "Destructive recursive delete on root, home, or wildcard."},
        {"id": "git-force-main", "category": "git", "pattern": r"\bgit\s+push\s+.*(--force|-f)\b.*\b(main|master|prod)\b|\bgit\s+push\s+(--force|-f)\b", "reason": "Force-push can overwrite shared git history."},
        {"id": "git-reset-hard", "category": "git", "pattern": r"\bgit\s+reset\s+--hard\b", "reason": "Hard reset discards uncommitted work."},
        {"id": "sql-drop-truncate", "category": "sql", "pattern": r"\b(DROP\s+(TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE)\b", "reason": "Destructive SQL DDL/truncation."},
        {"id": "net-exfil-pipe", "category": "network", "pattern": r"\b(curl|wget)\b.*(\|\s*(sh|bash|zsh|pwsh|python)|-d\s+@|\.(env|pem|key))", "reason": "Remote script execution or potential secret exfiltration."},
        {"id": "secret-dump", "category": "secrets", "pattern": r"\b(cat|type|printenv|env)\b.*\b(\.env|id_rsa|credentials|TOKEN|SECRET|API_KEY)\b", "reason": "Direct read/dump of secret or credential material."},
    ],
    "confirm_patterns": [
        {"id": "fs-rm", "category": "filesystem", "pattern": r"\b(rm|rmdir|del|Remove-Item)\b", "reason": "File or directory deletion requires confirmation."},
        {"id": "sql-delete-all", "category": "sql", "pattern": r"\bDELETE\s+FROM\b", "reason": "SQL DELETE statement modifies rows."},
        {"id": "net-outbound", "category": "network", "pattern": r"\b(curl|wget|Invoke-WebRequest|scp|rsync)\b", "reason": "Outbound network transfer."},
        {"id": "pkg-install", "category": "filesystem", "pattern": r"\b(pip\s+install|npm\s+install|apt-get\s+install)\b", "reason": "Dependency installation modifies environment."},
    ],
}


def _parse_simple_toml(text: str) -> Dict[str, Any]:
    if tomllib is not None:
        return tomllib.loads(text)
    # Minimal fallback for Python 3.9/3.10 if tomllib is absent
    data: Dict[str, Any] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if "=" in line and not line.startswith("["):
            k, v = [p.strip() for p in line.split("=", 1)]
            if v.startswith("["):
                data[k] = json.loads(v.replace("'", '"'))
            else:
                data[k] = v.strip('"\'')
    return data


def load_policy(policy_path: Optional[str | Path] = None) -> Dict[str, Any]:
    policy = json.loads(json.dumps(DEFAULT_POLICY))
    if not policy_path:
        return policy
    p = Path(policy_path)
    if not p.exists():
        raise FileNotFoundError(f"Policy file not found: {p}")
    raw = p.read_text(encoding="utf-8")
    custom = json.loads(raw) if p.suffix == ".json" else _parse_simple_toml(raw)

    for key in ("protected_paths",):
        if isinstance(custom.get(key), list):
            policy[key] = list(dict.fromkeys(policy[key] + custom[key]))
    for key in ("deny_patterns", "confirm_patterns"):
        if isinstance(custom.get(key), list):
            policy[key] = custom[key] + policy[key]
    return policy
