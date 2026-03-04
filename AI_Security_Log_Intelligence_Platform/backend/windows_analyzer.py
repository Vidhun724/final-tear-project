import re

def analyze_windows_log(filepath):
    
    failed_login_count = 0
    privilege_escalation = 0
    new_accounts = 0

    with open(filepath, "r", errors="ignore") as file:

        for line in file:

            line = line.lower()

            # Failed login
            if "4625" in line or "failed to log on" in line:
                failed_login_count += 1

            # Admin privilege assigned
            if "4672" in line:
                privilege_escalation += 1

            # New user created
            if "4720" in line:
                new_accounts += 1


    results = []

    # Lower threshold for testing
    if failed_login_count >= 5:
        results.append({
            "attack": "Brute Force Attack",
            "severity": "High",
            "evidence": f"{failed_login_count} failed login attempts detected"
        })

    if privilege_escalation > 0:
        results.append({
            "attack": "Privilege Escalation",
            "severity": "Critical",
            "evidence": f"{privilege_escalation} admin privilege events detected"
        })

    if new_accounts > 0:
        results.append({
            "attack": "Suspicious Account Creation",
            "severity": "Medium",
            "evidence": f"{new_accounts} new accounts created"
        })


    if not results:
        results.append({
            "attack": "No Threat Detected",
            "severity": "Safe",
            "evidence": "Logs appear normal"
        })


    return results