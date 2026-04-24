def analyze_edr(alerts):
    results = []

    for alert in alerts:
        if "attempts" in alert and alert["attempts"] > 5:
            results.append({
                "type": "Brute Force",
                "severity": "High",
                "status": "True Positive"
            })
        elif "process" in alert:
            results.append({
                "type": "Suspicious Execution",
                "severity": "Medium",
                "status": "Needs Investigation"
            })
    return results
