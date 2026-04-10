# Web Application Attack — Response Runbook

## Overview
Web application attacks target HTTP/HTTPS services. The most common types are SQL Injection, Cross-Site Scripting (XSS), Command Injection, and Directory Traversal. These attacks aim to extract data, gain server access, or compromise users.

## Detection Criteria
- Wazuh rule IDs: 31103, 31106, 31110, 31120 (Apache/Nginx WAF rules)
- Alert level: >= 7
- Triggers: Suspicious URL patterns (../../../, UNION SELECT, <script>, etc.)
- Log source: /var/log/apache2/access.log or /var/log/nginx/access.log

## MITRE ATT&CK Mapping
- Tactic: Initial Access (TA0001)
- Techniques:
  - T1190 — Exploit Public-Facing Application
  - T1059.007 — JavaScript (for XSS)
  - T1505.003 — Web Shell (if attacker gains server access)

## Severity Assessment
- CRITICAL: Successful command injection, web shell uploaded, database dumped
- HIGH: SQL injection returning data (HTTP 200 with large response), authentication bypass
- MEDIUM: Multiple failed injection attempts, directory traversal blocked
- LOW: Single automated scanner probe (Nikto, SQLmap first contact)

## Investigation Steps

### Step 1 — Analyze the malicious requests (3 min)
grep <SOURCE_IP> /var/log/apache2/access.log | tail -50
Look for:
- Response codes 200 (success) vs 403/404 (blocked)
- Unusually large response sizes (indicates data returned)
- Repeated similar patterns (automated scanning)
- Time between requests (< 1 sec = automated tool)

### Step 2 — Identify attack type from URL patterns (2 min)
SQL Injection indicators: UNION, SELECT, OR 1=1, --, '; DROP
Command Injection: ;ls, |whoami, $(id), `uname`
Directory Traversal: ../../../etc/passwd, ..%2F..%2F
XSS: <script>, javascript:, onerror=, onload=
LFI/RFI: ?page=../../, ?file=http://

### Step 3 — Determine if attack succeeded (3 min)
- HTTP 200 + large body size for a simple URL = data returned
- Check application logs for SQL errors exposed to user
- Check for new files in web directory: find /var/www -mmin -60 -type f
- Check for web shells: find /var/www -name "*.php" -newer /var/www/index.php

### Step 4 — Database integrity check (if SQL injection) (5 min)
Check for unusual database queries in application logs
Check if any credentials tables were accessed
Look for DB dumps: find / -name "*.sql" -mmin -120 2>/dev/null

## Remediation Actions

### Immediate (within 15 minutes)
1. Block the attacking IP:
   iptables -A INPUT -s <SOURCE_IP> -j DROP
2. If web shell found: remove it immediately and check for other backdoors
   find /var/www -name "*.php" -exec grep -l "eval\|base64_decode\|system\|exec" {} \;
3. If database compromise suspected: change all application database passwords

### Short-term (within 2 hours)
4. Deploy or update ModSecurity WAF rules
5. Review application input validation — patch the vulnerable parameter
6. Check and rotate all application credentials if SQL injection succeeded
7. Review web server user permissions — web server should not run as root

### Long-term (within 48 hours)
8. Full application security audit (OWASP Top 10 review)
9. Implement prepared statements / parameterized queries in all DB calls
10. Enable Content Security Policy (CSP) headers to prevent XSS
11. Set up automated vulnerability scanning (OWASP ZAP, Nikto) in CI/CD
12. Implement rate limiting on web application endpoints

## Indicators of Compromise (IOCs)
- Source IP performing attacks
- Attack payload URLs and parameters
- Response sizes indicating successful data extraction
- New files in web directory
- Modified application files
