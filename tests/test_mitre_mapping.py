
from detection.mitre_mapping import map_mitre_technique


def test_maps_suspicious_powershell():
    event = {
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc abc123",
        "parent_process": "cmd.exe",
    }

    detection = {
        "suspicious": True,
        "risk": "high",
        "reasons": ["PowerShell executou um comando potencialmente suspeito"],
    }

    result = map_mitre_technique(event, detection)

    assert result["technique_id"] == "T1059.001"
    assert result["confidence"] == "high"
    assert result["evidence"] == detection["reasons"]


def test_does_not_map_normal_powershell():
    event = {
        "process_name": "powershell.exe",
        "command_line": "powershell.exe",
        "parent_process": "explorer.exe",
    }

    detection = {
        "suspicious": False,
        "risk": "low",
        "reasons": [],
    }

    result = map_mitre_technique(event, detection)

    assert result is None


def test_maps_cmd_started_by_office():
    event = {
        "process_name": "cmd.exe",
        "command_line": "cmd.exe",
        "parent_process": "outlook.exe",
    }

    detection = {
        "suspicious": True,
        "risk": "medium",
        "reasons": ["Aplicativo Office iniciou um processo de script"],
    }

    result = map_mitre_technique(event, detection)

    assert result["technique_id"] == "T1059.003"
    assert result["confidence"] == "medium"


def test_does_not_map_unknown_suspicious_process():
    event = {
        "process_name": "wscript.exe",
        "command_line": "wscript.exe script.vbs",
        "parent_process": "winword.exe",
    }

    detection = {
        "suspicious": True,
        "risk": "medium",
        "reasons": ["Aplicativo Office iniciou um processo de script"],
    }

    result = map_mitre_technique(event, detection)

    assert result is None
