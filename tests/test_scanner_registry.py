# tests/test_scanner_registry.py
from pathlib import Path

from skill_auditor.inventory import inventory_skill
from skill_auditor.scanners import RULES, run_all

MAL = Path(__file__).parent / "fixtures" / "malicious_skill"
CLEAN = Path(__file__).parent / "fixtures" / "clean_skill"


def test_run_all_aggregates_every_scanner():
    cats = {f.category for f in run_all(inventory_skill(MAL))}
    for expected in {"DESTRUCTIVE", "RCE_SUPPLY_CHAIN", "EXFILTRATION", "PROMPT_INJECTION",
                     "OVER_PERMISSION", "OBFUSCATION", "SECRETS"}:
        assert expected in cats, f"missing {expected}"


def test_run_all_clean_is_empty():
    assert run_all(inventory_skill(CLEAN)) == []


def test_rules_catalog_lists_known_rule_ids():
    assert "PY-EXEC-001" in RULES
    assert RULES["SH-CURLPIPE-001"]["category"] == "RCE_SUPPLY_CHAIN"
