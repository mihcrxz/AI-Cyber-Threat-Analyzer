
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
    risk = "low"

    # Regra 1: PowerShell com argumentos suspeitos
    if process == "powershell.exe":
        if any(keyword in command_line for keyword in SUSPICIOUS_KEYWORDS):
            reasons.append(
                "PowerShell executou um comando potencialmente suspeito"
            )
            risk = "high"

    # Regra 2: Word iniciando processos de script
    if parent == "winword.exe":
        if process in {"powershell.exe", "cmd.exe", "wscript.exe"}:
            reasons.append(
                "Processo de script iniciado pelo Microsoft Word"
            )

            if risk != "high":
                risk = "medium"

    return {
        "suspicious": bool(reasons),
        "risk": risk,
        "reasons": reasons,
    }
