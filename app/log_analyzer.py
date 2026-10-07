import json


def load_security_logs():

    with open("data/security_logs.json", "r") as file:
        return json.load(file)


def analyze_logs():

    logs = load_security_logs()

    failed_logins = {}

    print("================================")
    print("       SECURITY LOG ANALYZER")
    print("================================")

    for log in logs:

        if log["event"] == "Failed login":

            ip = log["source_ip"]

            if ip not in failed_logins:
                failed_logins[ip] = 0

            failed_logins[ip] += 1

    print("\nFAILED LOGIN ANALYSIS")
    print("---------------------")

    for ip, count in failed_logins.items():

        print(
            "IP:",
            ip,
            "| Failed Attempts:",
            count
        )

        if count >= 3:

            print(
                "ALERT: Possible brute-force attack detected!"
            )


if __name__ == "__main__":
    analyze_logs()