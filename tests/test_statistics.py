
from analyzer.statistics import generate_statistics


def test_generate_statistics():
    results = [
        {
            "suspicious": True,
            "risk": "high",
            "reasons": ["PowerShell suspeito"],
        },
        {
            "suspicious": False,
            "risk": "low",
            "reasons": [],
        },
        {
            "suspicious": True,
            "risk": "medium",
            "reasons": ["Word iniciou PowerShell"],
        },
    ]

    statistics = generate_statistics(results)

    assert statistics["total_events"] == 3
    assert statistics["suspicious_events"] == 2
    assert statistics["normal_events"] == 1

    assert statistics["risk_levels"]["high"] == 1
    assert statistics["risk_levels"]["medium"] == 1
    assert statistics["risk_levels"]["low"] == 1


def test_empty_results():
    statistics = generate_statistics([])

    assert statistics["total_events"] == 0
    assert statistics["suspicious_events"] == 0
    assert statistics["normal_events"] == 0
