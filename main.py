


from analyzer.sysmon_reader import read_sysmon_events
from analyzer.report_generator import generate_report
from analyzer.statistics import generate_statistics
from detection.rules import analyze_event
from detection.mitre_mapping import map_mitre_technique


def main():
    print("=== AI CYBER THREAT ANALYZER ===")

    events = read_sysmon_events("data/sysmon_sample.json")
    results = []

    for index, event in enumerate(events, start=1):
        result = analyze_event(event)
        mitre = map_mitre_technique(event["process_name"])

        results.append(result)

        print(f"\n=== EVENTO {index} ===")
        print(f"Processo: {event['process_name']}")
        print(f"Processo pai: {event['parent_process']}")
        print(f"Suspeito: {result['suspicious']}")
        print(f"Risco: {result['risk']}")

        for reason in result["reasons"]:
            print(f"Motivo: {reason}")

        if mitre:
            print(f"MITRE: {mitre['technique_id']} - {mitre['technique_name']}")

        report_path = generate_report(event, result, mitre)
        print(f"Relatório: {report_path}")

    statistics = generate_statistics(results)

    print("\n=== RESUMO DA ANALISE ===")
    print(f"Total de eventos: {statistics['total_events']}")
    print(f"Eventos suspeitos: {statistics['suspicious_events']}")
    print(f"Eventos normais: {statistics['normal_events']}")

    print("\n=== DISTRIBUICAO DE RISCO ===")
    for risk, count in statistics["risk_levels"].items():
        print(f"{risk.upper()}: {count}")


if __name__ == "__main__":
    main()
