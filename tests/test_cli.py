# tests/test_cli.py
import json
from pathlib import Path

import pytest

from skill_auditor.cli import main

FIX = Path(__file__).parent / "fixtures"


def test_clean_skill_exits_zero(capsys):
    code = main(["--no-llm", str(FIX / "clean_skill")])
    assert code == 0


def test_malicious_skill_exits_two(capsys):
    code = main(["--no-llm", str(FIX / "malicious_skill")])
    assert code == 2


def test_json_output_is_valid(capsys):
    main(["--no-llm", "--json", str(FIX / "malicious_skill")])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["verdict"] == "block"
    assert data["findings"]


def test_missing_path_errors():
    with pytest.raises(SystemExit):
        main(["--no-llm", str(FIX / "does_not_exist")])
