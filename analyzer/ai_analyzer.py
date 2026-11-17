
def build_analysis_prompt(event: dict, result: dict, mitre: dict | None) -> str:
    prompt = f"""
Você é um analista especialista em segurança cibernética,
com experiência em análise de ameaças e operações SOC.

Analise o evento de segurança abaixo.

DADOS DO EVENTO:
- Processo: {event.get("process_name", "Desconhecido")}
- Processo pai: {event.get("parent_process", "Desconhecido")}
- Linha de comando: {event.get("command_line", "Não informada")}
- Usuário: {event.get("user", "Não informado")}

RESULTADO DA DETECÇÃO:
- Suspeito: {result.get("suspicious")}
- Nível de risco: {result.get("risk")}
- Motivos: {result.get("reasons", [])}

MITRE ATT&CK:
{mitre if mitre else "Nenhuma técnica mapeada."}

Com base exclusivamente nas evidências fornecidas:

1. Explique o comportamento observado.
2. Justifique a classificação de risco.
3. Identifique possíveis riscos de segurança.
4. Recomende ações de investigação para um analista SOC.

REGRAS:
- Não invente evidências.
- Diferencie fatos de hipóteses.
- Não considere um alerta como confirmação de ataque.
- Seja técnico, objetivo e claro.
"""
    return prompt.strip()



from openai import OpenAI, RateLimitError, APIConnectionError, APIStatusError
from dotenv import load_dotenv

load_dotenv()

client = OpenAI()


def generate_ai_analysis(prompt: str) -> str:
    try:
        response = client.responses.create(
            model="gpt-5.4-mini",
            input=prompt
        )

        return response.output_text

    except RateLimitError:
        return (
            "ANÁLISE DE IA INDISPONÍVEL: "
            "limite ou créditos da API esgotados."
        )

    except APIConnectionError:
        return (
            "ANÁLISE DE IA INDISPONÍVEL: "
            "falha de conexão com a OpenAI."
        )

    except APIStatusError as error:
        return (
            f"ANÁLISE DE IA INDISPONÍVEL: "
            f"erro da API ({error.status_code})."
        )

    except Exception as error:
        return f"ERRO INESPERADO NA ANÁLISE DE IA: {error}"
