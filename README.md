# Honeypot Reports

Wazuh Alert reports generated from a personal Dionaea honeypot, written to practice and demonstrate SOC analyst tradecraft: raw source validation, IOC enrichment, MITRE ATT&CK mapping, and detection gap analysis.

## About

This repo holds finished analysis from a honeypot I run in AWS. Each report starts from raw sensor data, gets enriched with open source threat intel, and ends with an assessment and concrete detection recommendations. The goal is not to collect alerts. The goal is to show I can take a hit from first contact to a decision a SOC would actually use.

Every report follows the same structure so they read consistently and so the methodology stays repeatable.

## Lab Architecture

```
Internet  ->  Dionaea honeypot (AWS EC2)
                  |
                  |  sqlite (ground truth)   +   JSON log
                  |
                  v
            Wazuh agent  ->  Wazuh manager (decoders + rules)
                                  |
                                  v
                        OpenSearch Dashboards (DQL hunting)
```

Dionaea writes connection data two ways: directly to a sqlite database at the moment of connection, and to a JSON log that the Wazuh agent tails. The sqlite database is treated as ground truth. The Wazuh and OpenSearch path is the SIEM view. Comparing the two is part of the process, not an afterthought.

## Methodology

Each report works the same seven steps. This keeps the analysis disciplined and makes every report comparable to the last.

1. Pivot on the indicator in raw source (sqlite) for ground truth count, protocol, transport, and time window.
2. Check for payloads (downloads table) to confirm whether anything was dropped or staged.
3. Enrich the source IP: reverse DNS, ASN and org, geolocation, AbuseIPDB, GreyNoise, and WHOIS abuse contact.
4. Characterize the behavior: connection rate, single port versus sweep, steady versus bursty.
5. Map MITRE ATT&CK from observed behavior, not from assumed intent.
6. Note detection gaps: confirm whether the expected rule fired and why or why not.
7. Write a BLUF and a recommendation a SOC can act on.

## Reports

| Date | Source IP | Activity | Disposition |
|---|---|---|---|
| 2026-06-26 | 61.230.69.104 | SMB reconnaissance on TCP/445 | No malware. Assessed as automated scanning (T1595.001). [Report](./smb-recon-61.230.69.104.md) |

## Tooling

| Function | Tool |
|---|---|
| Honeypot | Dionaea |
| SIEM | Wazuh |
| Search and dashboards | OpenSearch Dashboards (DQL) |
| Raw data analysis | sqlite3, Python, pandas |
| IP enrichment | IPinfo, AbuseIPDB, GreyNoise, APNIC WHOIS |
| Framework | MITRE ATT&CK |

## Notes

Infrastructure specifics (internal addressing, instance details, credentials) are intentionally left out of these reports. Attacker indicators are retained because they are the subject of the analysis. Timestamps are normalized to UTC.

These are personal lab reports. The activity described hit a honeypot built to attract it. Nothing here reflects a production environment.
