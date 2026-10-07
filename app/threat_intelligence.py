def check_threat_intelligence(iocs):

    results = []

    for ip in iocs["IP Addresses"]:

        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16."):
            results.append({
                "indicator": ip,
                "type": "IP",
                "reputation": "PRIVATE/INTERNAL",
                "risk": "LOW"
            })

        else:
            results.append({
                "indicator": ip,
                "type": "IP",
                "reputation": "UNKNOWN",
                "risk": "MEDIUM"
            })

    for domain in iocs["Domains"]:

        results.append({
            "indicator": domain,
            "type": "DOMAIN",
            "reputation": "UNKNOWN",
            "risk": "MEDIUM"
        })

    return results