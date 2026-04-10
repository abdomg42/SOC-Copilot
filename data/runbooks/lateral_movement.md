# Lateral Movement — Response Runbook

## Overview
Lateral movement is when an attacker who has compromised one system uses that access to move to other systems in the network. This is a critical phase — it indicates the attacker is expanding their foothold and the incident scope is wider than a single machine.

## Detection Criteria
- Wazuh rule IDs: 5710 (SSH from internal), 40116, 18107
- Alert level: >= 10
- Triggers:
  - SSH connections between internal hosts using unusual accounts
  - SMB authentication attempts within the network
  - Internal host scanning other internal hosts
  - Psexec, WMI, or remote service execution patterns

## MITRE ATT&CK Mapping
- Tactic: Lateral Movement (TA0008)
- Techniques:
  - T1021.004 — Remote Services: SSH
  - T1021.002 — Remote Services: SMB/Windows Admin Shares
  - T1563 — Remote Service Session Hijacking
  - T1550 — Use Alternate Authentication Material

## Severity Assessment
- CRITICAL: Attacker reached a domain controller, database server, or backup system
- HIGH: Attacker moved to a second production server from initial compromise
- MEDIUM: Internal scanning detected, no successful lateral connections yet
- LOW: Single failed lateral movement attempt, quickly blocked

## Investigation Steps

### Step 1 — Map the scope of movement (5 min)
On the INITIAL compromised host:
last -n 50                        # outgoing connections initiated
netstat -an | grep ESTABLISHED    # current active connections
grep "Accepted\|Failed" /var/log/auth.log | grep -v <INITIAL_IP>  # internal SSH

On the SIEM (Wazuh): search for alerts from the compromised host IP as SOURCE

### Step 2 — Identify the pivot path (3 min)
Build the chain: External_Attacker → Host_A → Host_B → Host_C
For each hop, identify:
- What credentials were used?
- What time did the movement occur?
- Were any new accounts created on destination hosts?

### Step 3 — Check for credential harvesting tools (3 min)
find / -name "mimikatz*" -o -name "hashdump*" -o -name "pwdump*" 2>/dev/null
Check for memory dump files: find / -name "*.dmp" -mmin -120 2>/dev/null
Check bash history for credential theft tools

### Step 4 — Identify all potentially compromised systems (5 min)
Build a list of all systems the attacker has touched or could have reached.
Check each identified system for:
- Unusual active sessions
- Recent account creations
- File modifications in sensitive directories

## Remediation Actions

### Immediate (within 10 minutes)
1. Network isolation: isolate ALL identified compromised hosts simultaneously
   (staggered isolation gives attacker time to destroy evidence)
2. Block all outbound connections from compromised hosts at firewall
3. Force logout of all active sessions on compromised hosts
4. Alert all affected system owners

### Short-term (within 2 hours)
5. Reset ALL credentials that may have been exposed on compromised hosts
   (SSH keys, service accounts, application passwords, database passwords)
6. Audit all accounts created in the last 48 hours across all systems
7. Review and revoke suspicious API tokens, service credentials
8. Inventory all systems the initial compromised account had access to

### Long-term (within 72 hours)
9. Full forensic image of all compromised hosts before returning to service
10. Implement network micro-segmentation — hosts should not freely SSH to each other
11. Deploy privileged access management (PAM) solution
12. Implement JIT (Just-in-Time) access for administrative operations
13. Enable detailed audit logging on all inter-host communications

## Indicators of Compromise (IOCs)
- All internal hosts that received connections from compromised host
- All user accounts used during lateral movement
- All timestamps of movement events
- Any tools dropped on intermediate hosts
- Network segments accessed

## Critical Note
Once lateral movement is confirmed, this is no longer a single-host incident.
Activate the full incident response procedure. Assume ALL systems on the same
network segment are potentially compromised until proven otherwise.
