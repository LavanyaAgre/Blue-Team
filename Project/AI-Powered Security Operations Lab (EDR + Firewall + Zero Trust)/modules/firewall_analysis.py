from collections import defaultdict

def analyze_firewall(file):
    ip_hits = defaultdict(int)

    with open(file) as f:
        for line in f:
            if "DENY" in line:
                ip = line.split()[2]
                ip_hits[ip] += 1

    suspicious = {ip: count for ip, count in ip_hits.items() if count > 1}
    return suspicious
