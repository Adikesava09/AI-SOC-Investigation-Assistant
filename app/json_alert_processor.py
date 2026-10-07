import json


def load_alerts():
    with open("data/security_alerts.json", "r") as file:
        return json.load(file)


def process_alerts():
    alerts = load_alerts()

    print("SOC ALERT QUEUE")
    print("================")

    for alert in alerts:
        print(f"\nAlert ID: {alert['id']}")
        print(f"Alert: {alert['alert']}")