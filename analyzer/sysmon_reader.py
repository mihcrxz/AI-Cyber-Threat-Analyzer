
import json
from pathlib import Path


def read_sysmon_event(file_path: str) -> dict:
    path = Path(file_path)

    with path.open("r", encoding="utf-8") as file:
        event = json.load(file)

    normalized_event = {
        "event_id": event.get("EventID"),
        "process_name": Path(event.get("Image", "")).name.lower(),
        "command_line": event.get("CommandLine", ""),
        "parent_process": Path(event.get("ParentImage", "")).name.lower(),
        "user": event.get("User", ""),
        "process_guid": event.get("ProcessGuid", ""),
        "parent_process_guid": event.get("ParentProcessGuid", ""),
    }

    return normalized_event
