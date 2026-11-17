
MITRE_MAPPING = {
    "powershell": {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic": "Execution",
        "reference": "https://attack.mitre.org/techniques/T1059/001/",
    },
    "command_interpreter": {
        "technique_id": "T1059.003",
        "technique_name": "Windows Command Shell",
        "tactic": "Execution",
        "reference": "https://attack.mitre.org/techniques/T1059/003/",
    },
}


def map_mitre_technique(event: dict, detection: dict) -> dict | None:
    process = str(event.get("process_name", "")).lower()
    parent = str(event.get("parent_process", "")).lower()

    suspicious = detection.get("suspicious", False)
    risk = detection.get("risk", "low")
    reasons = detection.get("reasons", [])

    # Não associa técnicas quando não existem evidências de suspeita.
    if not suspicious or not reasons:
        return None

    technique = None

    if process == "powershell.exe":
        technique = MITRE_MAPPING["powershell"]

    elif process == "cmd.exe" and parent in {
        "winword.exe",
        "excel.exe",
        "outlook.exe",
    }:
        technique = MITRE_MAPPING["command_interpreter"]

    if technique is None:
        return None

    confidence = "high" if risk == "high" else "medium"

    return {
        **technique,
        "confidence": confidence,
        "evidence": reasons,
        "detection_risk": risk,
    }
