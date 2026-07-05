# Network IDS Analysis: Priority-1 .onion DNS Queries (ET INFO 2014939)

Analyst: PumpkinEscobar |
Sensor: Suricata (LAN IDS) |
Date of activity: 04-05 Jul 2026 |
Date of report: 05 Jul 2026

## BLUF

A watchdog gate raised on Suricata Priority-1 alert volume. Every P1 in the
window resolves to a single signature: `1:2014939` **ET INFO DNS Query for TOR
Hidden Domain .onion**, fired by three LAN hosts (192.168.50.207, .7, .93)
sending `.onion` lookups to the AdGuard resolver at 192.168.50.140. All services
are active; this is not an infrastructure failure, and the gate was right to say
so.

It is **not** yet safe to call this "noise" and suppress it. `2014939` is an
ET **INFO** rule, but a `.onion` name reaching a clearnet DNS resolver is
anomalous by construction: Tor Browser resolves `.onion` internally and never
emits a system DNS query for it. Something on those three hosts is trying to
resolve a hidden-service name over ordinary DNS. Until the exact query name
(`dns.rrname`) is pulled and attributed to a process, disposition is
**PENDING** — benign-app-leak and malware-C2 both produce this exact alert. The
recommended action is to **identify the onion address first**, then apply a
*scoped* suppression, not the global `suppress sig_id 2014939` the auto-diagnosis
proposed.

## Activity Summary

| Field | Value |
|---|---|
| Signature | `1:2014939` ET INFO DNS Query for TOR Hidden Domain .onion |
| Priority | 1 |
| Sensor | Suricata (LAN IDS) |
| Source hosts (LAN) | 192.168.50.207, 192.168.50.7, 192.168.50.93 |
| Destination | 192.168.50.140:53 (AdGuard Home resolver) |
| Protocol | DNS (UDP/53, likely; confirm TCP/53 and DoT/DoH separately) |
| Query name (`dns.rrname`) | **Unknown — must be pulled from eve.json (see below)** |
| Resolver response | **Unknown — confirm NXDOMAIN vs. answer** |
| Malware verdict | PENDING attribution |
| Disposition | PENDING — do not suppress before qname is known |

The two Unknown rows are the whole investigation. Neither the alert count nor
the signature name tells you whether this is a user pasting a directory link or
a beacon. The query string does.

## Why an ET INFO rule still deserves a look

`2014939` matches any DNS question whose name ends in `.onion`. It is
informational because the *presence* of a Tor query is not, by itself, malicious.
But three facts make a clearnet `.onion` lookup worth reading before you mute it:

1. **Tor Browser does not do this.** The Tor client resolves `.onion` addresses
   inside the SOCKS layer. A correctly-working Tor setup produces **zero**
   system DNS queries for `.onion`. So this alert firing means the query came
   from something that is *not* routing through Tor — an app that saw an
   `.onion` string and naively tried to resolve it, or code that expects a
   Tor2Web / clearnet gateway to answer.
2. **RFC 7686 says the resolver should refuse it.** A compliant resolver returns
   NXDOMAIN for `.onion` and must not forward it to the public DNS. AdGuard Home
   handles this. So the *query* is what fired Suricata; the *answer* should be a
   dead end. Confirm that — a non-NXDOMAIN answer would be its own finding.
3. **Malware uses `.onion` for C2.** Families that hardcode an onion address and
   reach it via a Tor2Web gateway or a bundled proxy will emit exactly this
   query pattern. The alert cannot distinguish that from a curious user. The
   `dns.rrname` and the cadence can.

Benign explanations (common): a browser prefetching an `.onion` hyperlink seen
on a page, a user pasting a directory/mirror link (DuckDuckGo, a news site's
SecureDrop, a crypto exchange onion) into a normal browser, or an app with
optional Tor support misconfigured to use the system resolver. Malicious
explanations (must be ruled out): C2 beaconing to a hidden service, or a dropper
resolving a hardcoded onion. The triage below separates them.

## Investigation — pull the onion address

The signature name is on the wire; the query name is in `eve.json`. Run these on
the Suricata box.

**1. Extract every distinct onion queried, with per-host counts:**

```
jq -r 'select(.event_type=="dns" and (.dns.rrname // "" | endswith(".onion")))
       | [.src_ip, .dns.rrname] | @tsv' /var/log/suricata/eve.json \
  | sort | uniq -c | sort -rn
```

**2. Timing / cadence per host (beacon vs. one-off):** a human pasting a link
gives a handful of queries clustered in seconds. A beacon gives evenly-spaced
queries over hours. Bucket by minute:

```
jq -r 'select(.event_type=="dns" and (.dns.rrname // "" | endswith(".onion")))
       | [.src_ip, (.timestamp[0:16])] | @tsv' /var/log/suricata/eve.json \
  | sort | uniq -c
```

**3. Confirm the resolver answer (should be NXDOMAIN):** in the AdGuard Home
query log, filter the client IPs and the onion name. A returned A/AAAA record,
or forwarding to an upstream, is a misconfiguration and a separate finding.

**4. Attribute to a process on the noisiest host.** The alert names the host, not
the app. On that host:

```
# Linux
sudo ss -tunap | grep -i :53
sudo journalctl --since "-2h" | grep -i onion
# then correlate the timestamps to running processes / browser history
```

Assess the query name once you have it:

- **Known-good service mirror** (e.g. a well-known site's published onion, a
  SecureDrop address, an exchange's onion) + clustered human timing → benign
  user behavior. Scope a suppression, keep the signature live.
- **Random-looking v3 onion** (56 base32 chars) you cannot attribute + regular
  cadence → treat as possible C2. Isolate the host, pull the process, hash and
  submit the binary, do not suppress.

## MITRE ATT&CK Mapping (conditional)

Mapping depends on attribution; recorded here so the finding maps cleanly once
the qname is assessed.

| Condition | Tactic | Technique |
|---|---|---|
| Benign app/user leak | — | Not adversary behavior; no mapping |
| Confirmed C2 over hidden service | Command and Control | T1090.003 Proxy: Multi-hop Proxy (Tor) |
| Hardcoded onion resolution attempt | Command and Control | T1071.004 Application Layer Protocol: DNS |

## Detection Gaps and Recommendations

1. **Do not apply the global suppress the auto-diagnosis proposed.**
   `suppress gen_id 1, sig_id 2014939` silences the signature for *every* host
   and *every* onion name, permanently. If one of these hosts is later
   compromised and beacons to a hidden service, this rule is exactly what would
   catch it — and it would be blind. The auto-fix trades a real detection for a
   quiet dashboard.

2. **If suppression is warranted, scope it.** Two safer shapes:
   - Rate-limit instead of mute, so the signal survives but stops flooding P1:
     ```
     # /etc/suricata/threshold.config
     threshold gen_id 1, sig_id 2014939, type limit, track by_src, count 1, seconds 3600
     ```
   - Or suppress only the attributed host **after** the qname is confirmed
     benign, leaving detection intact for the other hosts:
     ```
     suppress gen_id 1, sig_id 2014939, track by_src, ip 192.168.50.207
     ```
   Reload with `sudo suricatasc -c reload-rules` after either change.

3. **Fix the P1 priority, not just the volume.** An ET INFO signature riding at
   Priority 1 is what tripped the gate. If this class of INFO alert should not
   page a human, reclassify it (drop it to P3 via `classification.config` /
   `metadata priority`) so genuine P1s are not buried — rather than suppressing
   the content outright.

4. **Add the `dns.rrname` to the alert surface.** The gate saw "1 issue" and a
   signature name but not the query string, which is the one field that decides
   disposition. Surface `dns.rrname` (and the resolver rcode) in the alert
   pipeline so the next occurrence is triageable without a manual eve.json pull.

5. **Baseline the three hosts.** Confirm whether .207/.7/.93 share a user, an
   app, or an image. Three hosts emitting the same anomalous query is either one
   person's device fleet (benign, easily scoped) or a common piece of software
   worth identifying — either answer shortens every future occurrence.

## Status

Open. Disposition is PENDING the `dns.rrname` pull (Investigation step 1) and
process attribution (step 4). This report is the analysis and the runbook; it
does not close the alert. Suppression is deferred until the onion address is
identified and assessed — that is the point of the finding, not a formality.
