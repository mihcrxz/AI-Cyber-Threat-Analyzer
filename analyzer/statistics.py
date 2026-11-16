
def generate_statistics(results: list) -> dict:
    statistics = {
        "total_events": len(results),
        "suspicious_events": 0,
        "normal_events": 0,
        "risk_levels": {
            "high": 0,
            "medium": 0,
            "low": 0,
        },
    }

    for result in results:
        if result["suspicious"]:
            statistics["suspicious_events"] += 1
        else:
            statistics["normal_events"] += 1

        risk = result["risk"].lower()

        if risk in statistics["risk_levels"]:
            statistics["risk_levels"][risk] += 1

    return statistics
