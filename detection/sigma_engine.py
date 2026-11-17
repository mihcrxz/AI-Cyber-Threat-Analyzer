
from pathlib import Path
import yaml


SIGMA_RULES_DIR = Path("rules/sigma")

FIELD_MAPPING = {
    "Image": "process_name",
    "ParentImage": "parent_process",
    "CommandLine": "command_line",
}


def load_sigma_rules():
    rules = []

    for rule_file in SIGMA_RULES_DIR.glob("*.yml"):
        with rule_file.open("r", encoding="utf-8") as file:
            rule = yaml.safe_load(file)

        if isinstance(rule, dict):
            rule["_source_file"] = rule_file.name
            rules.append(rule)

    return rules


def normalize_value(value):
    return str(value).lower()


def match_selection(selection, event):
    for field_operator, expected in selection.items():

        if "|" in field_operator:
            field, operator = field_operator.split("|", 1)
        else:
            field = field_operator
            operator = "equals"

        event_field = FIELD_MAPPING.get(field)

        if event_field is None:
            return False

        actual = normalize_value(event.get(event_field, ""))

        expected_values = (
            expected if isinstance(expected, list)
            else [expected]
        )

        matched = False

        for value in expected_values:
            value = normalize_value(value)

            if operator == "contains" and value in actual:
                matched = True

            elif operator == "endswith":
                suffix = value.replace("\\", "/").split("/")[-1]
                actual_name = actual.replace("\\", "/").split("/")[-1]

                if actual_name.endswith(suffix):
                    matched = True

            elif operator == "equals" and actual == value:
                matched = True

        if not matched:
            return False

    return True


def evaluate_sigma_rule(rule, event):
    detection = rule.get("detection", {})
    condition = detection.get("condition")

    if not isinstance(condition, str):
        return False

    selections = {
        name: match_selection(value, event)
        for name, value in detection.items()
        if name != "condition" and isinstance(value, dict)
    }

    parts = condition.lower().split()

    # Suporte às condições simples:
    # selection
    # selection_parent and selection_child
    if len(parts) == 1:
        return selections.get(parts[0], False)

    if len(parts) == 3 and parts[1] == "and":
        return (
            selections.get(parts[0], False)
            and selections.get(parts[2], False)
        )

    if len(parts) == 3 and parts[1] == "or":
        return (
            selections.get(parts[0], False)
            or selections.get(parts[2], False)
        )

    return False


def analyze_with_sigma(event):
    alerts = []

    for rule in load_sigma_rules():
        if evaluate_sigma_rule(rule, event):
            alerts.append({
                "rule": rule["title"],
                "rule_id": rule["id"],
                "level": rule["level"],
                "source_file": rule["_source_file"],
                "tags": rule.get("tags", []),
            })

    return alerts
