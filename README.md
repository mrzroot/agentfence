# agentfence

> **Dry-run capability firewall, blast-radius simulator, and hash-chained audit ledger for AI coding agents.**

[فارسی](README.fa.md) · [Interactive Firewall & Docs](https://mrzroot.github.io/agentfence/)

Before an AI agent runs a shell command, SQL query, or git operation, `agentfence` evaluates it against a local policy (`fence.toml`), simulates its filesystem blast radius without touching disk, and records every gate decision in a tamper-evident SHA-256 hash-chained ledger.

## Quick Start

```bash
pip install .
agentfence check "git push --force origin main" --json
agentfence run --ledger .agentfence/audit.jsonl -- pytest -q
agentfence verify-ledger .agentfence/audit.jsonl
```

## License

[MIT](LICENSE)
