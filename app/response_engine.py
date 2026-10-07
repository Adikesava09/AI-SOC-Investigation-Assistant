def recommend_response(alert, risk_level):

    if risk_level == "CRITICAL":
        return [
            "Immediately investigate the affected system",
            "Collect relevant security and endpoint logs",
            "Isolate the affected system if compromise is confirmed",
            "Investigate the source IP, domain or file",
            "Escalate the incident to SOC L2/Incident Response team"
        ]

    elif risk_level == "HIGH":
        return [
            "Investigate the source IP address",
            "Review authentication and security logs",
            "Check whether the user account is compromised",
            "Block the source IP if the attack is confirmed",
            "Escalate the incident to the SOC L2 team"
        ]

    elif risk_level == "MEDIUM":
        return [
            "Verify the user's activity",
            "Review relevant security logs",
            "Continue monitoring for additional activity"
        ]

    return [
        "Continue monitoring the alert",
        "Review relevant security logs"
    ]