
import json
from pathlib import Path

from analyzer.report_generator import generate_report


def test_generate_report_creates_json_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    event = {
        "event_id": 1,
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc abc123",
    }

    result = {
        "suspicious": True,
        "risk": "high",
        "reasons": ["PowerShell executou um comando potencialmente suspeito"],
    }

    mitre = {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic": "Execution",
    }

    report_path = generate_report(
    event,
    result,
    mitre,
    "Análise de IA de teste"
)

    

    assert Path(report_path).exists()
    assert report_path.endswith(".json")


def test_report_contains_correct_data(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    event = {"process_name": "powershell.exe"}
    result = {"suspicious": True, "risk": "high"}
    mitre = {"technique_id": "T1059.001"}

    report_path = generate_report(
    event,
    result,
    mitre,
    "Análise de IA de teste"
)

    with open(report_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    assert report["event"] == event
    assert report["detection"] == result
    assert report["mitre_attack"] == mitre
    assert "analysis_time" in report
