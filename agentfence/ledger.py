"""Tamper-evident SHA-256 hash-chained audit ledger for agent actions."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

GENESIS_HASH = "0" * 64


def _compute_hash(record_without_hash: Dict[str, Any]) -> str:
    canonical = json.dumps(record_without_hash, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def append_ledger(ledger_path: str | Path, entry: Dict[str, Any]) -> Dict[str, Any]:
    p = Path(ledger_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    prev_hash = GENESIS_HASH
    seq = 1
    if p.exists():
        lines = [l for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
        if lines:
            last = json.loads(lines[-1])
            prev_hash = last["hash"]
            seq = int(last["seq"]) + 1

    body = {
        "seq": seq,
        "ts": datetime.now(timezone.utc).isoformat(),
        "prev_hash": prev_hash,
        **entry,
    }
    record = {**body, "hash": _compute_hash(body)}
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record


def verify_ledger(ledger_path: str | Path) -> Dict[str, Any]:
    p = Path(ledger_path)
    if not p.exists():
        return {"valid": False, "entries": 0, "error": f"Ledger not found: {p}"}
    lines = [l for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    expected_prev = GENESIS_HASH
    for idx, line in enumerate(lines, start=1):
        try:
            rec = json.loads(line)
        except ValueError as exc:
            return {"valid": False, "entries": idx - 1, "broken_seq": idx, "error": f"Invalid JSON: {exc}"}
        if rec.get("prev_hash") != expected_prev:
            return {"valid": False, "entries": len(lines), "broken_seq": rec.get("seq", idx), "error": "prev_hash mismatch (chain broken)."}
        stored_hash = rec.get("hash")
        body = {k: v for k, v in rec.items() if k != "hash"}
        if _compute_hash(body) != stored_hash:
            return {"valid": False, "entries": len(lines), "broken_seq": rec.get("seq", idx), "error": "SHA-256 hash mismatch (record tampered)."}
        expected_prev = stored_hash
    return {"valid": True, "entries": len(lines), "head_hash": expected_prev}
