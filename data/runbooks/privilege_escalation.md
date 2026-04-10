# Privilege Escalation — Response Runbook

## Overview
Privilege escalation occurs when an attacker gains higher-level permissions than they should have. This is typically the step after initial access and before lateral movement or data exfiltration. Detection is critical because this step indicates the attacker is progressing through the kill chain.

## Detection Criteria
- Wazuh rule IDs: 5401, 5402, 5403 (sudo abuse), 5500 (setuid)
- Alert level: >= 10
- Triggers:
  - Unexpected sudo command execution by non-admin user
  - SUID/SGID file created or modified
  - /etc/passwd or /etc/sudoers modification
  - Unusual su or newgrp commands

## MITRE ATT&CK Mapping
- Tactic: Privilege Escalation (TA0004)
- Techniques:
  - T1548.003 — Sudo and Sudo Caching
  - T1548.001 — Setuid and Setgid
  - T1078 — Valid Accounts (with escalated privileges)
  - T1136 — Create Account

## Severity Assessment
- CRITICAL: Root shell obtained by non-root user, /etc/sudoers modified, new root account created
- HIGH: Sudo execution of sensitive commands (passwd, usermod, chmod 777 /etc/shadow)
- MEDIUM: SUID binary created in /tmp or user home directory
- LOW: Failed sudo attempt from non-privileged user

## Investigation Steps

### Step 1 — Verify the escalation occurred (3 min)
Check recent sudo usage:
grep "sudo:" /var/log/auth.log | tail -30
grep "COMMAND" /var/log/auth.log | grep -v "root" | tail -20

Check for new privileged accounts:
grep ":0:" /etc/passwd                    # UID 0 accounts (should be only root)
cat /etc/sudoers                          # unexpected entries
ls -la /etc/sudoers.d/                    # new files here are suspicious

### Step 2 — Check what was done with elevated privileges (5 min)
Review root command history if accessible:
cat /root/.bash_history
cat /root/.zsh_history

Check recently modified sensitive files:
find /etc -mmin -60 -type f 2>/dev/null
find /bin /sbin /usr/bin /usr/sbin -mmin -60 -type f 2>/dev/null

Check for new SUID binaries:
find / -perm -4000 -type f 2>/dev/null | grep -v "/usr/bin\|/usr/sbin\|/bin\|/sbin"

### Step 3 — Check for persistence mechanisms (5 min)
New cron jobs:
crontab -l -u root 2>/dev/null
ls -la /etc/cron*

New SSH keys:
cat /root/.ssh/authorized_keys
for user in $(cat /etc/passwd | cut -d: -f1); do
  cat /home/$user/.ssh/authorized_keys 2>/dev/null
done

New services:
systemctl list-units --type=service --state=running | grep -v default

### Step 4 — Identify the original compromised account (3 min)
Trace back from the escalation:
last -n 30                      # recent logins
who -a                          # current sessions
journalctl -u ssh --since "1 hour ago"

## Remediation Actions

### Immediate (within 10 minutes)
1. If active attacker session detected: terminate it immediately
   pkill -u <compromised_user>   # kill all processes of user
   usermod -L <compromised_user> # lock the account
2. Remove any unauthorized SUID binaries found
3. Revert any unauthorized changes to /etc/sudoers
4. If root persistence detected: consider taking the machine offline

### Short-term (within 1 hour)
5. Change passwords for all compromised and privileged accounts
6. Revoke and regenerate SSH keys for all admin accounts
7. Remove unauthorized authorized_keys entries
8. Review and clean up crontabs for all users
9. Check /tmp, /var/tmp for malicious files: find /tmp /var/tmp -type f -ls

### Long-term (within 24 hours)
10. Implement the principle of least privilege — audit sudoers file
11. Enable auditd for real-time privilege monitoring
12. Deploy Linux Security Module (AppArmor/SELinux) if not active
13. Implement immutable flag on sensitive files: chattr +i /etc/sudoers
14. Review all user accounts — remove unnecessary accounts
15. Full forensic investigation to determine initial compromise vector

## Indicators of Compromise (IOCs)
- Account(s) that performed escalation
- Commands executed with elevated privileges
- New files created with root ownership in unexpected locations
- Modifications to /etc/passwd, /etc/shadow, /etc/sudoers
- New or modified crontab entries
- New SUID/SGID binaries

## Escalation Criteria
Escalate immediately (full incident response) if:
- New root-level account was created
- Persistence mechanism was found (backdoor, cron, service)
- Data exfiltration evidence (large outbound transfers)
- Multiple systems appear to be affected (lateral movement)
