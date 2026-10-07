from datetime import datetime


def generate_report(alert_id, alert, alert_type, mitre, iocs, risk, actions):

    report = f"""
========================================
       SOC INVESTIGATION REPORT
========================================

Report Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Alert ID: {alert_id}

ALERT
-----
{alert}

CLASSIFICATION
--------------
Type: {alert_type}
MITRE ATT&CK: {mitre}

INDICATORS OF COMPROMISE
------------------------
IP Addresses: {iocs["IP Addresses"]}

RISK ASSESSMENT
---------------
Score: {risk["score"]}
Level: {risk["level"]}
Reason: {risk["reason"]}

RECOMMENDED RESPONSE
--------------------
"""

    for number, action in enumerate(actions, start=1):
        report += f"{number}. {action}\n"

    report += """
========================================
"""

    return report