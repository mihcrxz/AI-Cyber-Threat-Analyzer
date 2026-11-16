
from analyzer.sysmon_reader import read_sysmon_event
from analyzer.report_generator import generate_report
from detection.rules import analyze_event
from detection.mitre_mapping import map_mitre_technique


def main():
    print("=== AI CYBER THREAT ANALYZER ===")

    # 1. Ler evento Sysmon
    event = read_sysmon_event("data/sysmon_sample.json")

    # 2. Detectar comportamento suspeito
    result = analyze_event(event)

    # 3. Mapear técnica MITRE
    mitre = map_mitre_technique(event["process_name"])

    # 4. Exibir resultado
    print("\n=== RESULTADO DA ANALISE ===")
    print(f"Processo: {event['process_name']}")
    print(f"Processo pai: {event['parent_process']}")
    print(f"Suspeito: {result['suspicious']}")
    print(f"Risco: {result['risk']}")

    for reason in result["reasons"]:
        print(f"Motivo: {reason}")

    if mitre:
        print("\n=== MITRE ATT&CK ===")
        print(f"Tecnica: {mitre['technique_name']}")
        print(f"ID: {mitre['technique_id']}")
        print(f"Tatica: {mitre['tactic']}")

    # 5. Gerar relatório
    report_path = generate_report(event, result, mitre)

    print("\n=== RELATORIO GERADO ===")
    print(f"Arquivo: {report_path}")


if __name__ == "__main__":
    main()
