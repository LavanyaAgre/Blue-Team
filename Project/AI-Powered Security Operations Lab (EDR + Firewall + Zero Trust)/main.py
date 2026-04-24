import json
from modules.edr_analysis import analyze_edr
from modules.firewall_analysis import analyze_firewall
from modules.zero_trust_check import zero_trust

# Load EDR alerts
with open("data/edr_alerts.json") as f:
    alerts = json.load(f)

print("=== EDR ANALYSIS ===")
print(analyze_edr(alerts))

print("\n=== FIREWALL ANALYSIS ===")
print(analyze_firewall("data/firewall_logs.log"))

print("\n=== ZERO TRUST CHECK ===")
print(zero_trust("authorized", "secure"))
