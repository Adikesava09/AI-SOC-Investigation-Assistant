def calculate_risk(alert):
    alert_lower = alert.lower()

    if "failed login" in alert_lower or "brute force" in alert_lower:
        return {
            "score": 85,
            "level": "HIGH",
            "reason": "Multiple failed login attempts may indicate a brute-force attack."
        }

    elif "phishing" in alert_lower:
        return {
            "score": 90,
            "level": "CRITICAL",
            "reason": "A phishing attack may lead to credential theft or malware infection."
        }

    elif "malware" in alert_lower:
        return {
            "score": 95,
            "level": "CRITICAL",
            "reason": "Malware detection may indicate a compromised system."
        }

    elif "suspicious login" in alert_lower:
        return {
            "score": 65,
            "level": "MEDIUM",
            "reason": "Suspicious login activity requires verification."
        }

    return {
        "score": 30,
        "level": "LOW",
        "reason": "No high-risk pattern detected."
    }