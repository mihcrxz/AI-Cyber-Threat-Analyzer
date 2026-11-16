
SUSPICIOUS_KEYWORDS = (
    "-enc",
    "encodedcommand",
    "downloadstring",
    "invoke-expression",
    "mimikatz",
    "-nop",
    "-w hidden",
    "-windowstyle hidden",
    "-executionpolicy bypass",
)

OFFICE_PROCESSES = {
    "winword.exe",
    "excel.exe",
    "outlook.exe",
}

SCRIPT_PROCESSES = {
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
}


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

    # Regra 2: Aplicativos Office iniciando processos de script
    if parent in OFFICE_PROCESSES and process in SCRIPT_PROCESSES:
        reasons.append(
            "Aplicativo Office iniciou um processo de script"
        )

        if risk != "high":
            risk = "medium"

    return {
        "suspicious": bool(reasons),
        "risk": risk,
        "reasons": reasons,
    }


