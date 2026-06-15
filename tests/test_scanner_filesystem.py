# tests/test_scanner_filesystem.py
from skill_auditor.inventory import inventory_skill
from skill_auditor.models import Severity
from skill_auditor.scanners import filesystem


def _ids(tmp_path):
    return {f.rule_id for f in filesystem.scan(inventory_skill(tmp_path))}


def test_flags_path_traversal_in_python(tmp_path):
    (tmp_path / "a.py").write_text("data = open('../../etc/passwd').read()\n")
    assert "FS-TRAVERSAL-001" in _ids(tmp_path)


def test_flags_path_traversal_in_shell(tmp_path):
    (tmp_path / "run.sh").write_text("cat ../../secret > /tmp/x\n")
    assert "FS-TRAVERSAL-001" in _ids(tmp_path)


def test_flags_absolute_path_write(tmp_path):
    (tmp_path / "b.py").write_text("open('/etc/cron.d/evil', 'w').write('x')\n")
    findings = filesystem.scan(inventory_skill(tmp_path))
    hits = [f for f in findings if f.rule_id == "FS-ABSWRITE-001"]
    assert hits and hits[0].severity == Severity.HIGH
    assert hits[0].file == "b.py"


def test_relative_read_is_silent(tmp_path):
    (tmp_path / "c.py").write_text("open('data.txt')\nx = 1\n")
    assert filesystem.scan(inventory_skill(tmp_path)) == []
