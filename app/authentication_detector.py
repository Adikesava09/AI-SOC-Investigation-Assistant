import json


def detect_suspicious_authentication():

    with open("data/security_logs.json", "r") as file:
        logs = json.load(file)

    failed_ips = set()
    successful_ips = set()

    for log in logs:

        if log["event"] == "Failed login":
            failed_ips.add(log["source_ip"])

        elif log["event"] == "Successful login":
            successful_ips.add(log["source_ip"])

    print("================================")
    print(" AUTHENTICATION DETECTION ENGINE")
    print("================================")

    suspicious_ips = failed_ips.intersection(successful_ips)

    for ip in suspicious_ips:

        print("\nSuspicious IP:", ip)
        print("Reason: Failed login attempts followed by successful login")
        print("Risk: HIGH")
        print("Recommended Action: Investigate authentication logs")


if __name__ == "__main__":
    detect_suspicious_authentication()