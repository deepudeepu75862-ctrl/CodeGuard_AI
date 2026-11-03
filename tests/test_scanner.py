from backend.main import scan_source, risk_score, inspect_zip
import io, zipfile


def test_detects_eval():
    findings = scan_source("app.py", "result = eval(user_input)")
    assert any(item["id"] == "CG002" for item in findings)


def test_risk_score_is_bounded():
    findings = [{"severity": "High"} for _ in range(20)]
    assert risk_score(findings) == 100


def test_zip_inspection_reads_python_without_extracting():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("app.py", "print('hello')")
        archive.writestr("../escape.py", "print('unsafe path')")
    files, skipped = inspect_zip(stream.getvalue())
    assert "app.py" in files
    assert any("escape.py" in item for item in skipped)
