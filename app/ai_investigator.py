def generate_ai_analysis(alert, alert_type, risk, iocs):

    analysis = []

    analysis.append(
        f"The alert was classified as {alert_type}."
    )

    if iocs["IP Addresses"]:
        analysis.append(
            "An IP address was identified as an indicator of compromise."
        )

    if risk["level"] == "CRITICAL":
        analysis.append(
            "The alert requires immediate investigation because the risk level is critical."
        )

    elif risk["level"] == "HIGH":
        analysis.append(
            "The alert should be investigated with high priority."
        )

    elif risk["level"] == "MEDIUM":
        analysis.append(
            "The alert requires analyst verification."
        )

    else:
        analysis.append(
            "Continue monitoring for additional suspicious activity."
        )

    analysis.append(
        "The SOC analyst should correlate this alert with authentication, endpoint and network logs."
    )

    return analysis