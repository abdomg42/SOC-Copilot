# Data Exfiltration — Response Runbook

## Overview
Data exfiltration is the unauthorized transfer of data from a compromised system to an external location controlled by the attacker. This is often the final goal of an attack and indicates a successful breach with potentially severe business impact.

## Detection Criteria
- Wazuh rule IDs: 82000-82100 (network anomaly), custom high-volume outbound rules
- Alert level: >= 12
- Triggers:
  - Unusual large outbound data transfer (> 100MB in short time)
  - Database dump file created and transferred
  - Outbound traffic on unusual protocols (DNS tunneling, ICMP exfil)
  - Access to sensitive directories followed by outbound connection

## MITRE ATT&CK Mapping
- Tactic: Exfiltration (TA0010)
- Techniques:
  - T1041 — Exfiltration Over C2 Channel
  - T1048 — Exfiltration Over Alternative Protocol
  - T1567 — Exfiltration Over Web Service (Pastebin, cloud storage)
  - T1020 — Automated Exfiltration

## Severity Assessment
- CRITICAL: Database containing PII/credentials confirmed exfiltrated
- CRITICAL: Source code or intellectual property transferred externally
- HIGH: Large file transfer to external IP detected, content unknown
- MEDIUM: Unusual DNS query volume (potential DNS tunneling), no confirmed data loss

## Investigation Steps

### Step 1 — Quantify the transfer (3 min)
Check network traffic logs for outbound anomalies:
iftop -n                                      # real-time by IP
nethogs                                       # by process
# In Wazuh: search for alerts with bytes_out > 10000000 (10MB)

### Step 2 — Identify what was accessed before the transfer (5 min)
Check file access logs before the outbound transfer timestamp:
ausearch -f /etc/passwd --start <TIME> --end <TIME>
ausearch -k data-access --start <TIME>
find / -atime -1 -type f -ls 2>/dev/null | grep -v proc

Check database access logs for dumps or mass SELECTs:
# MySQL: grep "SELECT.*FROM" /var/log/mysql/mysql.log
# PostgreSQL: grep "SELECT" /var/log/postgresql/*.log

### Step 3 — Identify the destination (3 min)
ss -tnp at time of exfil (from logs if connection already closed)
Check DNS logs for suspicious domains: domains with high entropy names = DGA/C2
netstat history from logs: grep <DEST_IP> /var/log/

### Step 4 — Determine data sensitivity (5 min)
Identify what was in the directories accessed:
- /etc/shadow, /etc/passwd → credentials
- Database files → customer/business data
- SSH keys, certificates → authentication material
- Source code repositories → intellectual property
- Configuration files → infrastructure secrets

## Remediation Actions

### Immediate (within 5 minutes)
1. Block destination IP and domain immediately at firewall
2. Isolate the compromised host from network
3. Do NOT shut down the machine — preserve memory and process state for forensics
4. Notify legal/compliance team — mandatory if PII is involved

### Short-term (within 2 hours)
5. Invalidate all credentials that were potentially exposed:
   - SSH keys, API keys, database passwords, service accounts
6. Force password reset for all affected user accounts
7. Revoke all active tokens and sessions for affected services
8. Notify affected parties per data breach regulations if PII confirmed lost

### Long-term (within 72 hours)
9. Full forensic investigation to determine exact data volume and type
10. Legal notification timeline varies by regulation (GDPR: 72 hours)
11. Implement DLP (Data Loss Prevention) tools
12. Encrypt all sensitive data at rest and in transit
13. Implement data access logging and anomaly detection
14. Review and restrict which services can make outbound connections

## Regulatory Requirements (if PII involved)
- GDPR: Notify supervisory authority within 72 hours of discovery
- HIPAA: Notify within 60 days (breaches affecting < 500: annual summary)
- Document: what data, how many records, which individuals, notification plan

## Indicators of Compromise (IOCs)
- Destination IP/domain for exfiltration
- Volume of data transferred (bytes)
- Timestamps of access and transfer
- Source files or directories accessed
- Protocols used for exfiltration
- Attacker infrastructure details
