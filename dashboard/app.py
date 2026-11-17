
import streamlit as st
import json
import plotly.express as px
from pathlib import Path

st.set_page_config(
    page_title="AI Cyber Threat Analyzer",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI Cyber Threat Analyzer")
st.caption("Security Operations Center | Threat Monitoring")

st.divider()

st.subheader("Dashboard de Segurança")


# Carregar relatórios JSON
reports_dir = Path("reports")
reports = []

for file in reports_dir.glob("report_*.json"):
    try:
        with file.open("r", encoding="utf-8") as f:
            report = json.load(f)
            reports.append(report)
    except (json.JSONDecodeError, OSError) as error:
        st.warning(f"Não foi possível ler {file.name}: {error}")

st.subheader("Indicadores de Segurança")

if reports:
    total_events = len(reports)

    suspicious_events = sum(
        1 for report in reports
        if report["detection"]["suspicious"]
    )

    normal_events = total_events - suspicious_events

    high_risk = sum(
        1 for report in reports
        if report["detection"]["risk"] == "high"
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total de eventos", total_events)
    col2.metric("Eventos suspeitos", suspicious_events)
    col3.metric("Eventos normais", normal_events)
    col4.metric("Risco alto", high_risk)

    st.divider()
    st.subheader("Análise de Risco")

    risk_counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for report in reports:
        risk = report["detection"]["risk"].upper()
        if risk in risk_counts:
            risk_counts[risk] += 1

    col1, col2 = st.columns(2)

    with col1:
        risk_data = {
            "Nível de risco": list(risk_counts.keys()),
            "Quantidade": list(risk_counts.values())
        }

        fig_risk = px.bar(
            risk_data,
            x="Nível de risco",
            y="Quantidade",
            title="Distribuição de risco",
            color="Nível de risco"
        )

        st.plotly_chart(fig_risk, use_container_width=True)

    with col2:
        status_data = {
            "Status": ["Suspeitos", "Normais"],
            "Quantidade": [suspicious_events, normal_events]
        }

        fig_status = px.pie(
            status_data,
            names="Status",
            values="Quantidade",
            title="Eventos por classificação",
            hole=0.4
        )

        st.plotly_chart(fig_status, use_container_width=True)

    st.divider()
    st.subheader("Histórico de Alertas")

    import pandas as pd

    alert_data = []

    for report in reports:
        event = report["event"]
        detection = report["detection"]
        mitre = report.get("mitre_attack")

        alert_data.append({
            "Data": report["analysis_time"][:19].replace("T", " "),
            "Processo": event.get("process_name", "Desconhecido"),
            "Processo pai": event.get("parent_process", "Desconhecido"),
            "Usuário": event.get("user", "Desconhecido"),
            "Risco": detection.get("risk", "unknown").upper(),
            "MITRE": (
                mitre["technique_id"] if mitre else "Não mapeado"
            ),
            "Status": (
                "Suspeito" if detection["suspicious"] else "Normal"
            )
        })

    
    df_alerts = pd.DataFrame(alert_data)

    st.subheader("Filtros de Investigação")

    col1, col2, col3 = st.columns(3)

    with col1:
        risk_filter = st.selectbox(
            "Nível de risco",
            ["Todos", "HIGH", "MEDIUM", "LOW"]
        )

    with col2:
        process_options = ["Todos"] + sorted(
            df_alerts["Processo"].unique().tolist()
        )

        process_filter = st.selectbox(
            "Processo",
            process_options
        )

    with col3:
        user_filter = st.text_input(
            "Pesquisar usuário"
        )

    filtered_alerts = df_alerts.copy()

    if risk_filter != "Todos":
        filtered_alerts = filtered_alerts[
            filtered_alerts["Risco"] == risk_filter
        ]

    if process_filter != "Todos":
        filtered_alerts = filtered_alerts[
            filtered_alerts["Processo"] == process_filter
        ]

    if user_filter:
        filtered_alerts = filtered_alerts[
            filtered_alerts["Usuário"].str.contains(
                user_filter,
                case=False,
                na=False
            )
        ]

    st.dataframe(
        filtered_alerts,
        use_container_width=True,
        hide_index=True
    )

    st.caption(
        f"Exibindo {len(filtered_alerts)} de {len(df_alerts)} eventos."
    )

    st.divider()
    st.subheader("Investigação Individual")

    if not filtered_alerts.empty:
        selected_index = st.selectbox(
            "Selecione um alerta para investigar",
            filtered_alerts.index,
            format_func=lambda index: (
                f"{filtered_alerts.loc[index, 'Processo']} | "
                f"{filtered_alerts.loc[index, 'Risco']} | "
                f"{filtered_alerts.loc[index, 'Data']}"
            )
        )

        selected_report = reports[selected_index]

        event = selected_report["event"]
        detection = selected_report["detection"]
        mitre = selected_report.get("mitre_attack")


        st.markdown("### Resumo Executivo")

        risk_level = detection.get("risk", "").upper()
        status = "SUSPEITO" if detection.get("suspicious") else "NORMAL"

        st.write(f"**Classificação:** {status}")
        st.write(f"**Severidade:** {risk_level}")

        reasons = detection.get("reasons", [])

        if reasons:
            st.write(f"**Motivo principal:** {reasons[0]}")
        else:
            st.write("**Motivo principal:** Nenhum comportamento suspeito identificado.")

        if mitre:
            st.write(
                f"**MITRE ATT&CK:** {mitre['technique_id']} - "
                f"{mitre['technique_name']}"
            )
        else:
            st.write("**MITRE ATT&CK:** Não mapeado")

        
        ai_status = selected_report.get("ai_analysis")

        if ai_status is None or not ai_status.strip():
            st.info("Análise por IA não registrada.")

        elif "indispon" in ai_status.lower():
            st.warning(
                "Análise por IA indisponível. "
                "Verifique os créditos ou a conexão com a API."
            )

        else:
            st.success("Análise por IA disponível.")



        st.markdown("### Detalhes do evento")

        col1, col2 = st.columns(2)

        with col1:
            st.write("**Processo:**", event.get("process_name"))
            st.write("**Processo pai:**", event.get("parent_process"))
            st.write("**Usuário:**", event.get("user"))
            st.write("**Linha de comando:**", event.get("command_line"))

        with col2:
            st.write("**Process GUID:**", event.get("process_guid"))
            st.write("**Parent Process GUID:**", event.get("parent_process_guid"))
            st.write("**Risco:**", detection.get("risk", "").upper())
            st.write("**Suspeito:**", detection.get("suspicious"))

        st.markdown("### Motivos da detecção")

        for reason in detection.get("reasons", []):
            st.warning(reason)

        st.markdown("### MITRE ATT&CK")

        if mitre:
            st.write("**Técnica:**", mitre.get("technique_name"))
            st.write("**ID:**", mitre.get("technique_id"))
            st.write("**Tática:**", mitre.get("tactic"))
            st.link_button(
                "Consultar MITRE ATT&CK",
                mitre.get("reference")
            )
        else:
            st.info("Nenhuma técnica MITRE mapeada.")

        st.markdown("### Análise da IA")

        ai_analysis = selected_report.get(
            "ai_analysis",
            "Análise de IA não disponível."
        )

        st.write(ai_analysis)

        st.download_button(
            label="📥 Exportar relatório JSON",
            data=json.dumps(
                selected_report,
                indent=4,
                ensure_ascii=False
            ),
            file_name=f"alerta_{event.get('process_guid', 'relatorio')}.json",
            mime="application/json"
        )



        st.divider()
        st.markdown("### Recomendações de Resposta SOC")

        risk_level = detection.get("risk", "").lower()

        if risk_level == "high":
            st.error("Prioridade alta: investigação imediata recomendada.")

            recommendations = [
                "Validar a linha de comando executada pelo processo.",
                "Investigar a origem e o conteúdo do comando codificado.",
                "Verificar processos filhos e atividades subsequentes.",
                "Consultar outros eventos Sysmon relacionados ao mesmo Process GUID.",
                "Avaliar a necessidade de isolar o endpoint conforme os procedimentos do SOC."
            ]

        elif risk_level == "medium":
            st.warning("Prioridade moderada: investigar o contexto do evento.")

            recommendations = [
                "Verificar qual documento do Office iniciou o processo.",
                "Investigar a origem do documento e seus anexos.",
                "Consultar a árvore de processos relacionada.",
                "Verificar se houve conexões de rede ou execução de outros scripts."
            ]

        else:
            st.success("Baixa prioridade: manter monitoramento.")

            recommendations = [
                "Registrar o evento para fins de auditoria.",
                "Verificar se o comportamento é esperado no ambiente.",
                "Monitorar ocorrências semelhantes."
            ]

        for recommendation in recommendations:
            st.markdown(f"- {recommendation}")


    else:
        st.info("Nenhum alerta corresponde aos filtros selecionados.")

else:
    st.info("Nenhum relatório encontrado na pasta reports.")

