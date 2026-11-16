
from detection.rules import analyze_event


def test_detects_suspicious_powershell():
    event = {
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc abc123",
        "parent_process": "cmd.exe",
    }

    result = analyze_event(event)

    assert result["suspicious"] is True
    assert result["risk"] == "high"


def test_allows_normal_process():
    event = {
        "process_name": "notepad.exe",
        "command_line": "notepad.exe",
        "parent_process": "explorer.exe",
    }

    result = analyze_event(event)

    assert result["suspicious"] is False
    assert result["risk"] == "low"
    assert result["reasons"] == []


def test_detects_script_started_by_word():
    event = {
        "process_name": "powershell.exe",
        "command_line": "powershell.exe",
        "parent_process": "winword.exe",
    }

    result = analyze_event(event)

    assert result["suspicious"] is True
    assert result["risk"] == "medium"
    assert "Aplicativo Office iniciou um processo de script" in result["reasons"]

def test_detects_excel_starting_powershell():
    event = {
        "process_name": "powershell.exe",
        "command_line": "powershell.exe",
        "parent_process": "excel.exe",
    }

    result = analyze_event(event)

    assert result["suspicious"] is True
    assert result["risk"] == "medium"


def test_detects_outlook_starting_cmd():
    event = {
        "process_name": "cmd.exe",
        "command_line": "cmd.exe",
        "parent_process": "outlook.exe",
    }

    result = analyze_event(event)

    assert result["suspicious"] is True
    assert result["risk"] == "medium"
