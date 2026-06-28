# Wazuh Alert Report: SMB Reconnaissance from 61.230.69.104

Analyst: PumpkinEscobar |
Sensor: Dionaea honeypot (AWS EC2) |
Date of activity: 26 Jun 2026 |
Date of report: 28 Jun 2026

## BLUF

A Dionaea honeypot logged 1024 SMB connections to TCP/445 from 61.230.69.104 over roughly 10.5 minutes on 26 Jun 2026. The Wazuh SIEM surfaced 698 of those, a 326 event gap between raw sensor data and the SIEM. No malware was downloaded or staged. I assess this as external SMB reconnaissance (MITRE T1595.001) from a likely compromised residential host or botnet node on Taiwan's HiNet network. Intent is unconfirmed. The source is currently unreported on AbuseIPDB and GreyNoise.

## Activity Summary

| Field | Value |
|---|---|
| Source IP | 61.230.69.104 |
| Reverse DNS | 61-230-69-104.dynamic-ip.hinet.net |
| Target service | smbd (TCP/445) |
| Raw connections (sqlite) | 1024 |
| SIEM events (Wazuh) | 698 |
| Visibility gap | 326 events |
| Window, raw source | 2026-06-26 07:56:27 to 08:07:04 UTC |
| Window, SIEM | 2026-06-26 08:00:01 to 08:07:51 UTC |
| Duration | about 10 min 37 sec |
| Approx. rate | about 1.6 connections/sec, steady |
| Binaries dropped | 0 |

## Analysis

The source hit a single service (SMB/445) at a steady rate of about 1.6 connections per second. No protocol variation, no payload delivery, no exploitation follow-through. High volume against one port with nothing else behind it reads as automated service scanning, not a targeted intrusion attempt.

Reverse DNS resolves to dynamic-ip.hinet.net and WHOIS lists the netblock as Residential ADSL/FTTB on HiNet. Dedicated attack infrastructure rarely lives on residential dynamic IP space. The likelier explanation is a compromised host or a botnet node running opportunistic internet-wide SMB scanning. I am not attributing intent beyond that. The data supports scanning and nothing more.

Two separate issues showed up in the data, and they should not be confused for each other.

First, the raw source recorded 1024 connections while the SIEM surfaced 698, and the raw window opened about 3.5 minutes before the SIEM window. This is a pipeline and measurement difference. Dionaea logs to sqlite at the moment of connection. The Wazuh path crosses five stages before an event reaches the dashboard, and events can drop or stall along the way. The sqlite and JSON handlers in Dionaea are independent, and the agent reads the JSON, not the sqlite, so any shortfall in the JSON handler caps the SIEM count before Wazuh ever processes it.

Second, the high-volume rule never fired. That is a rule design issue, not a pipeline issue. Rule 100110 is a plain per-event match on port 445 with no frequency or timeframe condition, so it cannot produce a volume alert by design. 1024 connections in 10.5 minutes from one source should trip a threshold, and right now nothing is watching for that.

## Malware Disposition

Negative. A join against the Dionaea downloads table returned zero records for this source. No malware was downloaded, staged, or executed.

```
sudo sqlite3 /opt/dionaea/data/dionaea.sqlite \
"SELECT COUNT(*) FROM downloads d JOIN connections c \
ON d.connection=c.connection WHERE c.remote_host='61.230.69.104';"
0
```

## MITRE ATT&CK Mapping

| Tactic | Technique | Rationale |
|---|---|---|
| Reconnaissance | T1595.001 Active Scanning: Scanning IP Blocks | Pre-compromise, high-volume single-service probing of an internet-facing sensor. No access was gained, so post-access techniques do not apply. |

## Infrastructure Attribution

| Field | Value |
|---|---|
| ASN | AS3462 |
| Org | Chunghwa Telecom / HiNet, Data Communication Business Group |
| Netblock | 61.230.0.0 to 61.230.255.255 (HINET-NET) |
| Assignment | Residential ADSL/FTTB |
| Geo | Banqiao, Taipei, Taiwan |
| Abuse contact | abuse@hinet.net |

## Threat Intelligence Enrichment

| Source | Verdict |
|---|---|
| AbuseIPDB | Not reported as of 26 Jun 2026 |
| GreyNoise | No classification at time of review |
| IPinfo | Residential dynamic IP, HiNet TW |

## Detection Gaps and Recommendations

1. Investigate rule 100110. It matched on port 445 but carries no volume logic. Add a frequency and timeframe condition so repeated same-source hits to one port generate a high-volume alert.
2. Reconcile the SIEM to source gap. Confirm whether the 326 event shortfall and the late start are caused by the Dionaea JSON handler, agent buffering, or dashboard alert reduction. The quickest check is a line count of the source IP in dionaea.json compared against the sqlite count.
3. Add a MITRE tag to the SMB rule so future scans auto-map to T1595.001 in the dashboard.
4. Standardize report timestamps on UTC across the honeypot and SIEM views to avoid the timezone mismatch that masked the true start time.

## Appendix A: WHOIS

```
% Information related to '61.228.0.0 - 61.231.255.255'
% Abuse contact for '61.228.0.0 - 61.231.255.255' is 'abuse@hinet.net'

inetnum:        61.228.0.0 - 61.231.255.255
netname:        HINET-NET
descr:          Data Communication Business Group, Chunghwa Telecom Co., Ltd.
country:        TW
status:         ASSIGNED PORTABLE
abuse-mailbox:  abuse@hinet.net
source:         APNIC

% Information related to '61.230.0.0 - 61.230.255.255'

inetnum:        61.230.0.0 - 61.230.255.255
netname:        HINET-NET
descr:          Chunghwa Telecom Data Communication Business Group
country:        TW
status:         ASSIGNED NON-PORTABLE
remarks:        Residential ADSL/FTTB
source:         TWNIC
```

## Appendix B: Source IP Metadata (IPinfo)

```
ip:       61.230.69.104
hostname: 61-230-69-104.dynamic-ip.hinet.net
city:     Banqiao
region:   Taipei
country:  TW
loc:      25.0143,121.4672
org:      AS3462 Data Communication Business Group
timezone: Asia/Taipei
```
