SUSPICIOUS_KEYWORDS = (
    "-enc",
    "encodedcommand",
    "downloadstring",
    "invoke-expression",
    "mimikatz",
)


def analyze_event(event: dict) -> dict:
    process = str(event.get("process_name", "")).lower()
    command_line = str(event.get("command_line", "")).lower()
    parent = str(event.get("parent_process", "")).lower()

    reasons = []

    if process == "powershell.exe":
        if any(keyword in command_line for keyword in SUSPICIOUS_KEYWORDS):
            reasons.append(
                "PowerShell executou um comando potencialmente suspeito"
            )

    if parent == "winword.exe":
        if process in {"powershell.exe", "cmd.exe", "wscript.exe"}:
            reasons.append(
                "Processo de script iniciado pelo Microsoft Word"
            )

    return {
        "suspicious": bool(reasons),
        "risk": "high" if reasons else "low",
        "reasons": reasons,
    }