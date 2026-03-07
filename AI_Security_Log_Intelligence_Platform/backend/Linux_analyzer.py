def analyze_system_log(filepath):
    
    failed_ssh = 0
    sudo_usage = 0

    with open(filepath, "r", errors="ignore") as file:

        for line in file:

            line = line.lower()

            if "failed password" in line:
                failed_ssh += 1

            if "sudo:" in line:
                sudo_usage += 1


    results = []

    if failed_ssh >= 5:
        results.append({
            "attack": "SSH Brute Force Attempt",
            "severity": "High",
            "evidence": f"{failed_ssh} failed SSH login attempts detected"
        })

    if sudo_usage > 0 and sudo_usage <= 3:
        results.append({
            "attack": "Privilege Command Usage",
            "severity": "Low",
            "evidence": f"{sudo_usage} sudo commands executed"
        })


    if sudo_usage > 3:
            results.append({
            "attack": "Privilege Command Usage",
            "severity": "Medium",
            "evidence": f"{sudo_usage} sudo commands executed"
        })


    if not results:
        results.append({
            "attack": "No Threat Detected",
            "severity": "Safe",
            "evidence": "System logs appear normal"
        })


    return results