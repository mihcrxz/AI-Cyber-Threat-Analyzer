
import json
from pathlib import Path


def normalize_sysmon_event(event: dict) -> dict:
    return {
        "event_id": event.get("EventID"),
        "process_name": Path(event.get("Image", "")).name.lower(),
        "command_line": event.get("CommandLine", ""),
        "parent_process": Path(event.get("ParentImage", "")).name.lower(),
        "user": event.get("User", ""),
        "process_guid": event.get("ProcessGuid", ""),
        "parent_process_guid": event.get("ParentProcessGuid", ""),
    }


def read_sysmon_events(file_path: str) -> list:
    path = Path(file_path)

    with path.open("r", encoding="utf-8") as file:
        events = json.load(file)

    if not isinstance(events, list):
        raise ValueError("O arquivo precisa conter uma lista de eventos.")

    return [
        normalize_sysmon_event(event)
        for event in events
    ]

