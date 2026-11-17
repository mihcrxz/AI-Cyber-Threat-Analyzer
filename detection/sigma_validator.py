
from pathlib import Path
import yaml


SIGMA_RULES_DIR = Path("rules/sigma")


def validate_sigma_rules():
    rule_files = list(SIGMA_RULES_DIR.glob("*.yml"))

    if not rule_files:
        print("Nenhuma regra Sigma encontrada.")
        return

    for rule_file in rule_files:
        try:
            with rule_file.open("r", encoding="utf-8") as file:
                rule = yaml.safe_load(file)

            required_fields = [
                "title",
                "id",
                "status",
                "description",
                "logsource",
                "detection",
                "level",
            ]

            missing_fields = [
                field for field in required_fields
                if field not in rule
            ]

            if missing_fields:
                print(f"[INVALID] {rule_file.name}: campos ausentes {missing_fields}")
                continue

            if "condition" not in rule["detection"]:
                print(f"[INVALID] {rule_file.name}: condição ausente")
                continue

            print(f"[VALID] {rule_file.name}")

        except yaml.YAMLError as error:
            print(f"[INVALID] {rule_file.name}: erro YAML: {error}")

    print("\nValidação concluída.")


if __name__ == "__main__":
    validate_sigma_rules()
