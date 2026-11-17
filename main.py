


from analyzer.sysmon_reader import read_sysmon_events
from analyzer.report_generator import generate_report
from analyzer.statistics import generate_statistics
from detection.rules import analyze_event
from detection.mitre_mapping import map_mitre_technique
from analyzer.ai_analyzer import build_analysis_prompt
from analyzer.ai_analyzer import generate_ai_analysis

def main():
    print("=== AI CYBER THREAT ANALYZER ===")

    events = read_sysmon_events("data/sysmon_sample.json")
    results = []

    for index, event in enumerate(events, start=1):
        result = analyze_event(event)
        mitre = map_mitre_technique(event["process_name"])

        prompt = build_analysis_prompt(event, result, mitre)

        print("\n=== PROMPT PARA ANÁLISE COM IA ===")
        print(prompt)
        ai_analysis = generate_ai_analysis(prompt)
        print("\n=== ANÁLISE GERADA PELA IA ===")
        print(ai_analysis)

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

        report_path = generate_report(event, result, mitre, ai_analysis)
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
