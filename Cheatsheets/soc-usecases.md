| Use Case | MITRE ATT&CK | Simple Explanation | Prevention | Verdict |
|----------|-------------|-------------------|------------|---------|
| UC-001: Brute Force Detection | T1110 | Multiple password attempts to gain access | Enable MFA, account lockout | True Positive if repeated failures from same source |
| UC-002: User Login Monitoring | T1078 | Suspicious login (time/source/pattern) | Monitor login behavior, MFA | True Positive if success after failures |
| UC-003: New Local Admin Account | T1136, T1098 | New admin account created | Monitor account creation | True Positive if no approval |
| UC-004: Admin via net.exe | T1136, T1098 | Admin created using system command | Restrict net.exe usage | True Positive if unauthorized |
| UC-005: Service Account Login | T1078 | Service account used for login | Restrict interactive login | True Positive if unexpected usage |
| UC-006: Unusual Access | T1078 | Login from unusual system/time | Monitor baseline behavior | True Positive if no justification |
| UC-007: Suspicious PowerShell | T1059.001 | Malicious PowerShell command used | Enable logging, restrict usage | True Positive if encoded/malicious |
| UC-008: PowerShell Execution | T1059.001 | Normal or suspicious PowerShell usage | Monitor baseline | Benign if normal activity |
| UC-009: Long Command Line | T1027 | Long command used to hide payload | Monitor command length | True Positive if obfuscation |
| UC-010: Suspicious Arguments | T1059, T1027 | Malicious flags used in commands | Monitor arguments | True Positive if bypass detected |
| UC-011: Audit Log Cleared | T1070.001 | Logs deleted to hide activity | Restrict log access | True Positive if unauthorized |
| UC-012: Log Cleared (wevtutil) | T1070.001 | Logs cleared using tool | Monitor wevtutil usage | True Positive if suspicious |
| UC-013: Audit Log Tampering | T1562 | Logging disabled/modified | Protect audit settings | True Positive if unauthorized |
| UC-014: PowerShell History Cleared | T1070.003 | Command history deleted | Enable logging | True Positive if after attack |
| UC-015: Defender Tampering | T1562.001 | Antivirus disabled | Protect security tools | True Positive if disabled |
| UC-016: Security Driver Unloaded | T1562 | Security driver removed | Monitor system logs | True Positive if unauthorized |
| UC-017: Disable UAC | T1548 | UAC turned off | Enforce policies | True Positive if disabled |
| UC-018: UAC Bypass | T1548.002 | Privilege gained without prompt | Monitor elevation | True Positive if silent escalation |
| UC-019: Network Scanning | T1046 | Scanning multiple ports | Use IDS/IPS | True Positive if unauthorized |
| UC-020: Port Scanning | T1046 | Scanning one system ports | Monitor connections | True Positive if repeated |
| UC-021: Rogue DNS | T1071.004 | Using unauthorized DNS | Enforce DNS policy | True Positive if suspicious domains |
| UC-022: TOR Traffic | T1090.003 | Using TOR network | Block TOR nodes | True Positive if unauthorized |
| UC-023: Unencrypted Traffic | T1041 | HTTP data transfer | Enforce HTTPS | True Positive if sensitive data |
| UC-024: Large Upload | T1041 | Large data upload outside | Use DLP tools | True Positive if sensitive data |
| UC-025: Geo Anomaly | T1078 | Login from unusual country | Geo restrictions | True Positive if unexplained |
| UC-026: BITS Download | T1105 | Malware download via BITS | Restrict BITS usage | True Positive if malicious file |
| UC-027: BITS Persistence | T1547 | Persistent BITS job | Monitor jobs | True Positive if unauthorized |
| UC-028: CertUtil Decode | T1140 | Decode hidden payload | Monitor certutil | True Positive if malicious |
| UC-029: CertUtil Download | T1105 | Download using certutil | Block URLs | True Positive if execution |
| UC-030: CertUtil VerifyCtl | T1105 | Hidden download via verifyctl | Monitor commands | True Positive if suspicious |
| UC-031: Rare LOLBAS Usage | T1036 | Unusual use of legit tools | Baseline behavior | True Positive if abnormal |
| UC-032: NTFS ADS | T1564.004 | Hidden data in files | Monitor ADS | True Positive if malicious |
| UC-033: ADS via LOLBAS | T1564.004 | Hidden payload via legit tools | Restrict LOLBAS | True Positive if execution |
| UC-034: Logon Scripts | T1037 | Script runs at startup | Monitor registry/scripts | True Positive if unauthorized |
| UC-035: Scheduled Task Abuse | T1053 | Task runs malware | Monitor tasks | True Positive if suspicious |
| UC-036: Suspicious Service Path | T1543 | Service runs malicious file | Monitor services | True Positive if suspicious |
| UC-037: Service CMD/PowerShell | T1543 | Service executes commands | Restrict configs | True Positive if malicious |
| UC-038: Winlogon Persistence | T1547.004 | Runs malware at login | Monitor registry | True Positive if unknown binary |
| UC-039: Recurring Malware | T1053, T1547 | Malware runs repeatedly | Monitor processes | True Positive if persistence |
| UC-040: Malware Execution | T1204 | Malware actively running | Use EDR | True Positive if confirmed |
| UC-041: Shadow Copy Deletion | T1490 | Backup deleted (ransomware) | Restrict vssadmin | True Positive if no maintenance |
| UC-042: LSASS Access | T1003.001 | Passwords stolen from memory | Enable protections | True Positive if unauthorized |
| UC-043: Mimikatz Execution | T1003 | Credential dump tool used | Block tools | True Positive if executed |
| UC-044: PowerShell Download | T1059.001, T1105 | Malware downloaded via PowerShell | Restrict scripts | True Positive if unknown file |
| UC-045: Encoded PowerShell | T1027 | Hidden PowerShell command | Decode & monitor | True Positive if malicious |
| UC-046: Unusual Admin Login | T1078 | Suspicious admin login | MFA, monitoring | True Positive if unauthorized |
| UC-047: New Admin Account | T1136 | Admin account created | Monitor accounts | True Positive if no approval |
| UC-048: RDP Brute Force | T1110 | Multiple RDP login attempts | Lockout + MFA | True Positive if threshold exceeded |
| UC-049: Data Exfiltration | T1041 | Data sent outside | DLP + monitoring | True Positive if sensitive data |
| UC-050: C2 Communication | T1071 | System talks to attacker server | Block IPs | True Positive if beaconing |
