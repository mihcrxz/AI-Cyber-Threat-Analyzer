
from analyzer.sysmon_reader import read_sysmon_events
from detection.sigma_engine import analyze_with_sigma


def main():
    events = read_sysmon_events("data/sysmon_sample.json")

    for index, event in enumerate(events, start=1):
        alerts = analyze_with_sigma(event)

        print(f"\n=== EVENTO {index} ===")
        print(f"Processo: {event['process_name']}")

        if alerts:
            for alert in alerts:
                print(f"Regra Sigma: {alert['rule']}")
                print(f"Severidade: {alert['level']}")
        else:
            print("Nenhum alerta Sigma.")


if __name__ == "__main__":
    main()
