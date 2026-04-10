# SSH Brute Force Attack — Response Runbook

## Overview
A brute force SSH attack occurs when an attacker systematically tries username/password combinations to gain unauthorized access to a system via SSH. This is one of the most common attack types observed in SOC environments.

## Detection Criteria
- Wazuh rule IDs: 5710, 5711, 5712, 5716
- Alert level: >= 8
- Trigger: > 10 failed SSH authentication attempts within 60 seconds from the same source IP
- Log pattern: "Failed password for [user] from [IP]" in /var/log/auth.log

## MITRE ATT&CK Mapping
- Tactic: Credential Access (TA0006)
- Technique: T1110 — Brute Force
- Sub-technique: T1110.001 — Password Guessing

## Severity Assessment
- CRITICAL: > 100 attempts + at least 1 successful login detected after failures
- HIGH: > 50 attempts, no successful login, targeting privileged accounts (root, admin, sudo)
- MEDIUM: 10-50 attempts, no successful login, targeting regular accounts
- LOW: < 10 attempts, all failed, known scanner IP

## Investigation Steps

### Step 1 — Confirm the attack (2 min)
Check auth.log for the pattern:
grep "Failed password" /var/log/auth.log | grep <SOURCE_IP> | tail -50
grep "Accepted password" /var/log/auth.log | grep <SOURCE_IP>
If any "Accepted password" lines exist after the failures → CRITICAL, escalate immediately.

### Step 2 — Identify targeted accounts (2 min)
grep "Failed password for" /var/log/auth.log | grep <SOURCE_IP> | awk '{print $9}' | sort | uniq -c | sort -rn
Note which usernames were targeted — root/admin targeting is more severe.

### Step 3 — Check if attacker IP is known (1 min)
Query AbuseIPDB or VirusTotal for the source IP reputation.
Check if the IP appeared in previous alerts.

### Step 4 — Verify system integrity (5 min)
If any successful login was detected:
- Check for new user accounts: cat /etc/passwd | tail -5
- Check running processes: ps aux | grep -v "$(ps aux | head -1)"
- Check recently modified files: find / -mmin -30 -type f 2>/dev/null | head -20
- Check authorized_keys: cat /root/.ssh/authorized_keys; cat /home/*/.ssh/authorized_keys

## Remediation Actions

### Immediate (within 15 minutes)
1. Block the attacking IP at the firewall:
   iptables -A INPUT -s <SOURCE_IP> -j DROP
   ip6tables -A INPUT -s <SOURCE_IP> -j DROP
2. If successful login detected: isolate the machine from the network immediately
3. Disable password authentication for SSH (if not already):
   sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
   systemctl restart sshd

### Short-term (within 1 hour)
4. Enable and configure fail2ban:
   apt install fail2ban -y
   systemctl enable fail2ban && systemctl start fail2ban
5. Add the attacker subnet to a persistent blocklist if multiple IPs from same /24
6. Reset credentials of all targeted accounts as a precaution
7. Review all currently active SSH sessions: who -a && last -n 20

### Long-term (within 24 hours)
8. Enforce SSH key-only authentication across all servers
9. Change SSH port from default 22 to a non-standard port (e.g., 2222)
10. Implement Multi-Factor Authentication (MFA) for SSH
11. Set up geographic IP blocking if attacks consistently originate from specific countries
12. Document the incident in the security log with timeline and actions taken

## Indicators of Compromise (IOCs)
- Source IP performing the brute force
- Usernames targeted (especially root, admin, ubuntu)
- Timestamps of attack window
- Any successful authentication events during or after the attack window

## Escalation Criteria
Escalate to senior analyst if:
- Any successful login was detected from the attacking IP
- Attacker pivoted to internal network addresses
- New user accounts were created during or after the attack window
- System files were modified after a successful login
