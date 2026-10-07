import os
import requests


def check_ip_reputation(ip):

    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return {
            "indicator": ip,
            "reputation": "API KEY NOT CONFIGURED",
            "risk": "UNKNOWN"
        }

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": api_key
    }

    try:

        response = requests.get(
            url,
            headers=headers,
            timeout=10
        )

        if response.status_code != 200:
            return {
                "indicator": ip,
                "reputation": "API ERROR",
                "risk": "UNKNOWN"
            }

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious = stats.get("malicious", 0)

        if malicious > 0:
            risk = "HIGH"
        else:
            risk = "LOW"

        return {
            "indicator": ip,
            "reputation": f"Malicious detections: {malicious}",
            "risk": risk
        }

    except Exception:

        return {
            "indicator": ip,
            "reputation": "CONNECTION ERROR",
            "risk": "UNKNOWN"
        }


if __name__ == "__main__":

    result = check_ip_reputation("8.8.8.8")

    print("================================")
    print("   THREAT INTELLIGENCE RESULT")
    print("================================")

    print("Indicator:", result["indicator"])
    print("Reputation:", result["reputation"])
    print("Risk:", result["risk"])