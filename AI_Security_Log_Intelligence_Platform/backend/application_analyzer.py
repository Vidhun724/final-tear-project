def analyze_application_log(filepath):
    
    unauthorized_access = 0
    failed_login = 0
    sql_errors = 0

    with open(filepath, "r", errors="ignore") as file:

        for line in file:

            line = line.lower()

            if "unauthorized access" in line:
                unauthorized_access += 1

            if "failed login" in line:
                failed_login += 1

            if "sql syntax error" in line or "sql error" in line:
                sql_errors += 1


    results = []

    if unauthorized_access > 0:
        results.append({
            "attack": "Unauthorized Access Attempt",
            "severity": "High",
            "evidence": f"{unauthorized_access} unauthorized access events detected"
        })

    if failed_login >= 3:
        results.append({
            "attack": "Application Brute Force Attempt",
            "severity": "Medium",
            "evidence": f"{failed_login} failed login attempts detected"
        })

    if sql_errors > 0:
        results.append({
            "attack": "Possible SQL Injection",
            "severity": "Critical",
            "evidence": f"{sql_errors} SQL related errors detected"
        })


    if not results:
        results.append({
            "attack": "No Threat Detected",
            "severity": "Safe",
            "evidence": "Application logs appear normal"
        })


    return results