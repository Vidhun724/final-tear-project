def analyze_webserver_log(filepath):
    
    sql_injection = 0
    directory_traversal = 0
    scanning_attempt = 0

    with open(filepath, "r", errors="ignore") as file:

        for line in file:

            line = line.lower()

            if "' or 1=1" in line or "sql" in line:
                sql_injection += 1

            if "../" in line:
                directory_traversal += 1

            if "404" in line:
                scanning_attempt += 1


    results = []

    if sql_injection > 0:
        results.append({
            "attack": "Possible SQL Injection Attempt",
            "severity": "Critical",
            "evidence": f"{sql_injection} suspicious SQL patterns detected"
        })

    if directory_traversal > 0:
        results.append({
            "attack": "Directory Traversal Attempt",
            "severity": "High",
            "evidence": f"{directory_traversal} directory traversal requests detected"
        })

    if scanning_attempt >= 5:
        results.append({
            "attack": "Web Scanning Activity",
            "severity": "Medium",
            "evidence": f"{scanning_attempt} repeated 404 requests detected"
        })

    if not results:
        results.append({
            "attack": "No Threat Detected",
            "severity": "Safe",
            "evidence": "Web server logs appear normal"
        })

    return results