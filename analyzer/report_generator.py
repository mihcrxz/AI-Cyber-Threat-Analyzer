
import json
from datetime import datetime, timezone
from pathlib import Path


def generate_report(event: dict, result: dict, mitre: dict | None) -> str:
    report = {
        "analysis_time": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "detection": result,
        "mitre_attack": mitre,
    }

    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = reports_dir / f"report_{timestamp}.json"

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)

    return str(report_path)
