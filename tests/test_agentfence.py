import json
import sys
from pathlib import Path

from agentfence.analyzer import check_command
from agentfence.cli import main
from agentfence.ledger import verify_ledger


def test_blocks_destructive_commands_and_allows_safe(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x=1", encoding="utf-8")
    (tmp_path / ".env").write_text("SECRET=123", encoding="utf-8")

    r_rm = check_command("rm -rf /", cwd=str(tmp_path))
    assert r_rm["verdict"] == "deny" and r_rm["risk_score"] >= 90

    r_git = check_command("git push --force origin main", cwd=str(tmp_path))
    assert r_git["verdict"] == "deny"

    r_sql = check_command("psql -c 'DROP TABLE users;'", cwd=str(tmp_path))
    assert r_sql["verdict"] == "deny"

    r_env = check_command("cat .env", cwd=str(tmp_path))
    assert r_env["verdict"] == "deny" and ".env" in r_env["blast_radius"]["protected_hits"]

    r_glob = check_command("rm src/*.py", cwd=str(tmp_path))
    assert r_glob["verdict"] == "confirm"
    assert "src/a.py" in r_glob["blast_radius"]["estimated_files"]

    r_ok = check_command("pytest -q src/a.py", cwd=str(tmp_path))
    assert r_ok["verdict"] == "allow"


def test_run_and_tamper_evident_ledger(tmp_path: Path, capsys):
    ledger = tmp_path / "audit.jsonl"
    assert main(["check", "rm -rf /", "--json"]) == 1
    capsys.readouterr()

    assert main(["run", "--ledger", str(ledger), "--cwd", str(tmp_path), "--", sys.executable, "-c", "print('safe')"]) == 0
    assert main(["run", "--ledger", str(ledger), "--cwd", str(tmp_path), "--", "git", "push", "--force", "origin", "main"]) == 1
    assert main(["verify-ledger", str(ledger), "--json"]) == 0
    v = json.loads(capsys.readouterr().out)
    assert v["valid"] is True and v["entries"] == 2

    # Tamper with line 1 -> verify_ledger must detect it
    lines = ledger.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace('"executed": true', '"executed": false')
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert verify_ledger(ledger)["valid"] is False
    assert main(["verify-ledger", str(ledger)]) == 1
