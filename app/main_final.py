import json

from alert_analyzer import analyze_alert
from ioc_extractor import extract_iocs
from risk_engine import calculate_risk
from threat_intelligence import check_threat_intelligence
from response_engine import recommend_response
from report_generator import generate_report
from ai_investigator import generate_ai_analysis
from db_operations import save_alert


with open("data/security_alerts.json", "r") as file:
    alerts = json.load(file)


print("================================")
print("   AI SOC INVESTIGATION ASSISTANT")
print("================================")


for alert_data in alerts:

    alert_id = alert_data["id"]
    alert = alert_data["alert"]

    print("\n================================")
    print(f"ALERT ID: {alert_id}")
    print("================================")

    # Alert Analysis
    analysis = analyze_alert(alert)

    # IOC Extraction
    print("\nIOC INFORMATION")
    print("----------------")

    iocs = extract_iocs(alert)

    print("IP Addresses:", iocs["IP Addresses"])
    print("Domains:", iocs["Domains"])
    print("URLs:", iocs["URLs"])
    print("Hashes:", iocs["Hashes"])

    # Threat Intelligence
    print("\nTHREAT INTELLIGENCE")
    print("-------------------")

    threat_results = check_threat_intelligence(iocs)

    for result in threat_results:
        print(
            result["indicator"],
            "|",
            result["type"],
            "|",
            result["reputation"],
            "|",
            result["risk"]
        )

    # Risk
    print("\nRISK ASSESSMENT")
    print("----------------")

    risk = calculate_risk(alert)

    print("Risk Score:", risk["score"])
    print("Risk Level:", risk["level"])
    print("Reason:", risk["reason"])

    # Response
    print("\nRECOMMENDED RESPONSE")
    print("--------------------")

    actions = recommend_response(
        alert,
        risk["level"]
    )

    for number, action in enumerate(actions, start=1):
        print(f"{number}. {action}")

    # AI Investigation
    print("\nAI INVESTIGATION")
    print("----------------")

    ai_analysis = generate_ai_analysis(
        alert,
        analysis["type"],
        risk,
        iocs
    )

    for point in ai_analysis:
        print("-", point)

    # Save to database
    ioc_text = ", ".join(iocs["IP Addresses"])

    save_alert(
        alert_id,
        alert,
        analysis["type"],
        analysis["mitre"],
        risk["score"],
        risk["level"],
        ioc_text
    )

    print("\n[+] Alert saved to SOC database.")

    # Report
    report = generate_report(
        alert_id,
        alert,
        analysis["type"],
        analysis["mitre"],
        iocs,
        risk,
        actions
    )

    print("\nINVESTIGATION REPORT")
    print("--------------------")
    print(report)

    # Save report to file
    report_file = f"reports/report_{alert_id}.txt"

    with open(report_file, "w") as file:
        file.write(report)

    print(f"[+] Report saved: {report_file}")