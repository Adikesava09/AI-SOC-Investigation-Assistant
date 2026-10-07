import json


def detect_advanced_events():

    with open("data/security_logs.json", "r") as file:
        logs = json.load(file)

    print("================================")
    print("     ADVANCED SOC DETECTOR")
    print("================================")

    for log in logs:

        event = log["event"].lower()
        message = log["message"].lower()

        # Suspicious PowerShell
        if "powershell" in event or "powershell" in message:

            print("\n[ALERT] Suspicious PowerShell Activity")
            print("Source IP:", log["source_ip"])
            print("Username:", log["username"])
            print("Risk: HIGH")
            print("MITRE ATT&CK: T1059.001 - PowerShell")
            print("Action: Investigate PowerShell execution")

        # Port Scanning
        elif "port scan" in event or "port scan" in message:

            print("\n[ALERT] Possible Port Scanning")
            print("Source IP:", log["source_ip"])
            print("Risk: HIGH")
            print("MITRE ATT&CK: T1046 - Network Service Scanning")
            print("Action: Investigate source IP and network traffic")

        # Privilege Escalation
        elif "privilege" in event or "privilege" in message:

            print("\n[ALERT] Possible Privilege Escalation")
            print("Source IP:", log["source_ip"])
            print("Username:", log["username"])
            print("Risk: CRITICAL")
            print("Action: Investigate account and system activity")

        # Suspicious DNS
        elif "dns" in event or "dns" in message:

            print("\n[ALERT] Suspicious DNS Activity")
            print("Source IP:", log["source_ip"])
            print("Risk: MEDIUM")
            print("Action: Investigate DNS query and destination domain")


if __name__ == "__main__":
    detect_advanced_events()