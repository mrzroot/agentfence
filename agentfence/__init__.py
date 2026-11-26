"""agentfence — Dry-run capability firewall, blast-radius simulator, and hash-chained audit ledger."""

__version__ = "1.0.0"

from .analyzer import check_command
from .ledger import append_ledger, verify_ledger
from .policy import load_policy

__all__ = ["__version__", "check_command", "append_ledger", "verify_ledger", "load_policy"]
