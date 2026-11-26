# Changelog

## [1.0.0] - 2026-11-26

### Added
- `agentfence check`: policy engine (`fence.toml` / JSON) with risk scoring, `allow`/`confirm`/`deny` verdicts, and read-only filesystem blast-radius simulation.
- `agentfence run`: pre-execution policy gate logging every allowed/blocked action to a SHA-256 hash-chained `.agentfence/audit.jsonl`.
- `agentfence verify-ledger`: tamper-evident hash chain verification.
- Interactive bilingual (EN / فارسی) browser firewall & blast-radius simulator on GitHub Pages.
