# AI-Powered SOC Alert Triage

Objective
Automate initial triage of security alerts using AI to reduce analyst workload.

Data
Authentication logs with failed login attempts.

Approach
- Parsed logs using Python
- Identified repeated failed login attempts per IP
- Used AI to classify alerts and assign severity

Output
- Alert Type: Brute Force Attempt
- Severity: Medium
- Classification: True Positive
- Explanation: Multiple failed attempts from same IP indicate possible attack

Value
- Reduces manual triage time
- Helps SOC analysts prioritize alerts faster
- Demonstrates practical AI integration in security workflows
