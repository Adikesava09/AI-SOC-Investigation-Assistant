def analyze_alert(alert):
    alert_lower = alert.lower()

    print("SOC ALERT ANALYZER")
    print("------------------")
    print("Alert:", alert)

    if "failed login" in alert_lower or "brute force" in alert_lower:
        result = {
            "type": "Brute Force",
            "mitre": "T1110 - Brute Force",
            "risk": "HIGH",
            "action": "Investigate the source IP and review authentication logs."
        }

    elif "phishing" in alert_lower:
        result = {
            "type": "Phishing",
            "mitre": "T1566 - Phishing",
            "risk": "HIGH",
            "action": "Analyze the email, sender, URL and attachments."
        }

    elif "malware" in alert_lower:
        result = {
            "type": "Malware",
            "mitre": "T1204 - User Execution",
            "risk": "HIGH",
            "action": "Isolate the affected system and investigate the malware."
        }

    elif "suspicious login" in alert_lower:
        result = {
            "type": "Suspicious Login",
            "mitre": "T1078 - Valid Accounts",
            "risk": "MEDIUM",
            "action": "Verify the user's login activity and source IP."
        }

    else:
        result = {
            "type": "Unknown",
            "mitre": "Not mapped",
            "risk": "LOW",
            "action": "Further investigation required."
        }

    print("Type:", result["type"])
    print("MITRE ATT&CK:", result["mitre"])
    print("Risk:", result["risk"])
    print("Action:", result["action"])

    return result