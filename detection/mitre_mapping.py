
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


def map_mitre_technique(process_name: str) -> dict | None:
    process = process_name.lower()

    if process == "powershell.exe":
        return MITRE_MAPPING["powershell"]

    if process == "cmd.exe":
        return MITRE_MAPPING["command_interpreter"]

    return None
