import os
import requests


def investigate_with_llm(alert, risk_level, iocs):

    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        return "LLM API key is not configured."


    prompt = f"""
You are a SOC analyst.

Analyze this security alert.

Alert:
{alert}

Risk Level:
{risk_level}

Indicators:
{iocs}

Provide:

1. Alert summary
2. Possible attack type
3. Investigation steps
4. Recommended response
5. MITRE ATT&CK technique if applicable

Keep the response concise.
"""


    response = requests.post(
        "https://api.openai.com/v1/responses",

        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        },

        json={
            "model": "gpt-5.6-mini",
            "input": prompt
        },

        timeout=30
    )


    if response.status_code != 200:

        return (
            "LLM request failed. "
            f"HTTP status: {response.status_code}"
        )


    data = response.json()

    return data.get(
        "output_text",
        "No analysis returned."
    )


if __name__ == "__main__":

    result = investigate_with_llm(

        "Multiple failed login attempts from 203.0.113.50",

        "HIGH",

        {
            "IP Addresses": ["203.0.113.50"],
            "Domains": [],
            "URLs": [],
            "Hashes": []
        }
    )

    print("================================")
    print("       LLM INVESTIGATION")
    print("================================")

    print(result)