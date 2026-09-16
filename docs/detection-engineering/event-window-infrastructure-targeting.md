# Detection Engineering: Critical-Infrastructure Targeting in Political Event Windows

**Status:** draft for review
**Scope:** defensive detection logic for the elevated-risk period surrounding summits, ministerials, elections, and multilateral meetings
**Audience:** SOC detection engineers, OT security, CTI analysts

---

## 0. What this document is, and what it deliberately is not

This is **behavior-based detection engineering**. Every hypothesis below keys on an
observable action taken against infrastructure the defender owns — an authentication
attempt, a protocol write, a traffic volume shift, a configuration change.

This document does **not** attempt to identify, profile, or attribute individuals.
Nationality, residence, inferred ethnicity, commit-time zone, language of code
comments, and account geography are **not threat signals** and appear nowhere in the
logic below. They generate false positives at an enormous rate, they are trivially
spoofed by any actor who cares, and using them produces accusations against
uninvolved developers. Attribution of a campaign to a named actor is a CTI judgment
made after the fact from corroborated evidence, not a detection input.

Detections fire on **what was done to your estate**, never on **who someone appears to be**.

---

## 1. Why the event window is a useful detection primitive

Political event windows change the defender's math in three ways that are directly
exploitable for detection:

1. **Adversary tempo compresses.** Hacktivist and state-aligned disruption operations
   are timed for media coverage. Activity that would otherwise be spread over months
   concentrates into days. ENISA's 2025 landscape records pro-Russia DDoS waves timed
   to electoral events, aligned with concurrent information operations.
2. **Defender baseline shifts predictably.** Traffic to public-facing government,
   venue, transport, and press assets rises for legitimate reasons. Naive
   volume-threshold alerting drowns. Detections must be baselined *against the event
   profile*, not against the quiet-period profile.
3. **Change freeze creates a clean signal.** Most operators freeze production change
   during the window. A configuration write to an OT device during a declared freeze
   is a near-zero-false-positive event. **This is the single highest-value detection
   in the document.**

### Window definition

Anchor all logic to a declared window, expressed relative to event start `T`:

| Phase | Range | Dominant activity | Detection posture |
|---|---|---|---|
| `RECON` | T-30d → T-7d | Scanning, exposure enumeration, credential harvesting, lure infrastructure registration | Hunt-heavy, low alerting |
| `STAGE` | T-7d → T-1d | Access attempts, phishing delivery, booter capacity tests, target lists published | Alerting, freeze begins |
| `ACTIVE` | T-1d → T+2d | Disruption, defacement, DDoS, OT manipulation | Max sensitivity, freeze enforced |
| `TAIL` | T+2d → T+7d | Persistence, exfil, claim-of-responsibility, cleanup | Retro-hunt, integrity verification |

Implement the window as a **lookup/watchlist table** (`event_window`) joined into rule
logic, not as hardcoded dates. Rules reference `phase`, never literals.

---

## 2. Threat model: four archetypes that matter in this window

These are behavioral classes, not attributions. A given campaign may span several.

### A. Volumetric disruption (highest frequency, lowest sophistication)
Public-administration web assets hit with L3/4 and L7 floods. ENISA attributes 96.2%
of hacktivist-claimed attacks to DDoS, with public administration the single most
targeted sector at 38% of recorded EU incidents. Volunteer-client botnets
(DDoSia-style) distribute target lists via Telegram and coordinate short, sharp waves.
**Defensive implication:** availability is the target. Detection value is in *early
wave identification and target-list correlation*, not in blocking after the fact.

### B. Opportunistic OT access (highest impact per incident)
Internet-exposed control devices reached over minimally secured remote-access paths.
Two well-documented patterns:
- **Unitronics Vision-series PLC/HMI** exploitation: Shodan/Censys enumeration of
  TCP/20256, authentication with default or absent passwords, then ladder-logic erase
  and replacement, device rename, version downgrade, upload/download disable, port
  change, and HMI defacement.
- **Exposed VNC to SCADA/HMI**: pro-Russia hacktivist groups accessing OT control
  devices over minimally secured internet-facing VNC (CISA AA25-343A).

**Defensive implication:** these are *not* sophisticated intrusions. They are
credential and exposure failures. Detection is cheap and reliable.

### C. Faketivism / state-aligned persona operations
State-aligned intrusion sets operating under hacktivist branding — ENISA cites Cyber
Army of Russia Reborn (Sandworm-nexus) and CyberAv3ngers (IRGC-nexus) as examples,
and notes Z-Pentest was stood up by CARR and NoName057(16) administrators reusing CARR
TTPs. **Defensive implication:** do not downgrade response severity because a claim
looks like low-tier hacktivism. Treat the TTP, not the branding.

### D. Access operations against the event itself
Credential phishing with event-themed lures (accreditation, agenda changes, venue
logistics, press credentials) against delegations, secretariat staff, vendors, and
press. Objective is collection, not disruption; it is the quietest and most likely to
survive the window undetected.

---

## 3. Detection hypotheses

Each hypothesis states: the adversary behavior, the data required, the logic, the
expected false positives, and the ATT&CK mapping. Detections are numbered `DH-n`.

---

### DH-1 — Unsolicited inbound enumeration of OT service ports

**Behavior.** Pre-event reconnaissance enumerating internet-reachable control-system
services to build a target list.

**Data.** Perimeter firewall accept/deny logs, Zeek `conn.log`, NetFlow at the
internet edge.

**Logic.** Count distinct destination IPs contacted by a single source on OT-relevant
ports within a rolling hour. The ports carry near-zero legitimate inbound internet
traffic, so the threshold can be aggressive.

```
OT_PORTS = 502/tcp   (Modbus)        102/tcp   (S7comm)
           20000/tcp (DNP3)          44818/tcp (EtherNet/IP)
           47808/udp (BACnet)        20256/tcp (Unitronics PCOM)
           5900-5910/tcp (VNC)       4840/tcp  (OPC UA)
```

```sql
-- Generic SIEM pseudo-SQL; translate to your query language
SELECT src_ip, COUNT(DISTINCT dst_ip) AS fanout,
       COUNT(DISTINCT dst_port) AS port_spread,
       MIN(ts) AS first_seen
FROM network_conn
WHERE direction = 'inbound'
  AND dst_port IN (502,102,20000,44818,47808,20256,4840)
     OR dst_port BETWEEN 5900 AND 5910
GROUP BY src_ip, window(ts, 1h)
HAVING fanout >= 5 OR (fanout >= 2 AND port_spread >= 3)
```

**Enrichment, not filtering.** Annotate hits with source ASN and known-scanner status
(Shodan/Censys/Shadowserver publish their ranges). Research scanners are *expected* and
their presence tells you the asset is publicly enumerable — that is itself a finding
worth an exposure ticket. Do not suppress them silently.

**False positives.** Legitimate research scanning; internal vulnerability scanners
misconfigured to scan from an external egress IP; ISP-level CGNAT aggregation.

**ATT&CK.** T0842 Network Sniffing / T0846 Remote System Discovery (ICS); T1595 Active
Scanning (Enterprise).

**Phase weighting.** Alert at `RECON` severity *low* (feeds the exposure backlog);
escalate to *high* if the same source reappears in `STAGE`/`ACTIVE` with an auth attempt.

---

### DH-2 — Authentication against control devices with default or absent credentials

**Behavior.** Direct authentication to PLC/HMI using vendor defaults, or successful
session establishment where no authentication is configured at all.

**Data.** Device auth logs where available; VNC server logs; Zeek `rfb.log` for VNC
session negotiation; PCOM/Modbus session records from an OT-aware sensor (Nozomi,
Claroty, Dragos, or Zeek with ICS parsers).

**Logic — VNC leg (Zeek `rfb.log`):**

```yaml
title: Inbound VNC session to OT segment with weak or no authentication
id: 7a1c4e02-9d33-4f5a-b2c7-0f6ac9e11b84
status: experimental
description: >
  Detects externally-sourced VNC sessions terminating in an OT/DMZ segment where the
  negotiated auth type is None (1) or the session was established on first attempt.
  Maps to pro-Russia hacktivist OT access tradecraft described in CISA AA25-343A.
logsource:
  product: zeek
  service: rfb
detection:
  external_source:
    src_ip|cidr|not:
      - '10.0.0.0/8'
      - '172.16.0.0/12'
      - '192.168.0.0/16'
  ot_destination:
    dst_ip|cidr: '%OT_SEGMENTS%'      # populate from asset inventory
  weak_auth:
    auth_method: 1                     # rfbSecurityNone
  authenticated_ok:
    auth: true
  condition: external_source and ot_destination and (weak_auth or authenticated_ok)
falsepositives:
  - Sanctioned vendor remote-support session (should be jump-host mediated, not direct)
  - Engineering workstation reachable via misconfigured NAT
level: critical
tags:
  - attack.ics.t0822      # External Remote Services
  - attack.ics.t0812      # Default Credentials
```

**Logic — Unitronics PCOM leg.** Any inbound TCP/20256 session from a non-allowlisted
source that reaches established state is an alert at *critical*, with no volume
threshold. There is no legitimate reason for this port to be internet-reachable.

**False positives.** Genuinely rare. A hit here is either a real intrusion or an
exposure that must be closed the same day. Treat both as incidents.

**ATT&CK.** T0812 Default Credentials; T0822 External Remote Services; T0883 Internet
Accessible Device.

---

### DH-3 — Control-logic or device-configuration write during declared change freeze

**This is the highest-confidence detection in this document.** Deploy it first.

**Behavior.** Program download, firmware change, device rename, protection-mode
change, or communication-parameter change on an OT asset while change is frozen.
Observed in the Unitronics pattern as logic erase → custom logic upload → rename →
version downgrade → upload/download disable → port change.

**Data.** OT protocol sensor function-code decoding; PLC/engineering-workstation
change logs; historian config audit; vendor change records.

**Logic.**

```sql
SELECT ts, src_ip, dst_ip, protocol, function_code, asset_id, operator_account
FROM ot_protocol_events
JOIN event_window w ON ts BETWEEN w.freeze_start AND w.freeze_end
WHERE function_code IN (
        'program_download',      -- S7comm / PCOM / CIP program transfer
        'firmware_update',
        'device_rename',
        'write_protection_change',
        'comm_parameter_write',
        'mode_change_run_stop'
      )
  AND NOT EXISTS (
        SELECT 1 FROM approved_change_requests c
        WHERE c.asset_id = ot_protocol_events.asset_id
          AND ts BETWEEN c.window_start AND c.window_end
          AND c.status = 'approved'
      )
```

**False positives.** Emergency change executed without a ticket. That is itself a
process finding worth surfacing — do not tune it away, route it to change management.

**ATT&CK.** T0843 Program Download; T0857 System Firmware; T0836 Modify Parameter;
T0858 Change Operating Mode.

**Note on the freeze.** The detection is only as good as the freeze declaration. Get
freeze windows into the SIEM as structured data *before* `STAGE`, with named approvers
and an exception path. A freeze that lives in an email thread is not a detection input.

---

### DH-4 — Coordinated L7 flood against event-adjacent public assets

**Behavior.** Short, high-intensity HTTP floods from a distributed volunteer client
base, targeting published lists of government, transport, banking, and venue sites.

**Data.** CDN/WAF logs, reverse-proxy access logs, edge NetFlow.

**Logic.** Volume alone is wrong here — legitimate event traffic also spikes. Key on
the *shape* of the traffic instead:

```kql
// Kusto / Azure Monitor — adapt field names to your WAF schema
let event_assets = _GetWatchlist('event_window_assets') | project Host;
WAFLogs
| where TimeGenerated > ago(15m)
| where Host in (event_assets)
| summarize
    rps            = count() / 900.0,
    uniq_src       = dcount(ClientIP),
    uniq_ua        = dcount(UserAgent),
    uniq_path      = dcount(UriPath),
    cache_miss_pct = 100.0 * countif(CacheStatus == "MISS") / count(),
    err5xx_pct     = 100.0 * countif(StatusCode >= 500) / count()
    by Host, bin(TimeGenerated, 1m)
| extend ua_per_src   = uniq_ua / todouble(uniq_src),
         path_entropy = uniq_path / todouble(uniq_src)
// Flood signature: many sources, shallow path diversity, cache-bypassing, UA churn
| where rps > 3 * toscalar(baseline_rps_for_phase)
    and uniq_src > 500
    and path_entropy < 1.5
    and cache_miss_pct > 60
| order by TimeGenerated asc
```

**The discriminator is `path_entropy` and `cache_miss_pct`.** Real event traffic is
cache-friendly and path-diverse (people browse). Floods hammer few paths with
cache-busting query strings. `baseline_rps_for_phase` must come from the *event*
baseline, refreshed daily through the window.

**False positives.** A genuine news-driven traffic surge (a leak, a resignation, a
protest) will produce high `rps` and high `uniq_src` — but *high* path entropy and
*low* cache-miss. That is why both discriminators are required.

**ATT&CK.** T1498 Network Denial of Service; T1499 Endpoint Denial of Service.

---

### DH-5 — Event-themed credential phishing against delegation and staff identities

**Behavior.** Lures referencing accreditation, agenda revisions, venue logistics,
security briefings, press credentials, or bilateral scheduling. Typically AiTM
credential capture rather than malware.

**Data.** Mail gateway detonation logs, Entra ID / Okta sign-in logs, newly-observed-
domain feeds, certificate transparency.

**Logic — two legs, correlated.**

*Leg 1 — infrastructure pre-positioning (runs from `RECON`):* monitor certificate
transparency and NOD feeds for registrations combining the event's name, host city,
year, and accreditation/registration/portal tokens. Age-weight: domains registered
inside the window and immediately issued a certificate are the interesting set.

*Leg 2 — post-capture session anomaly (Entra ID):*

```kql
let event_staff = _GetWatchlist('event_accredited_identities') | project UserPrincipalName;
SigninLogs
| where UserPrincipalName in (event_staff)
| where ResultType == 0
| extend Device = tostring(DeviceDetail.deviceId),
         Compliant = tostring(DeviceDetail.isCompliant)
// AiTM tell-tales: token replay from a different network/device than enrollment,
// and MFA satisfied by claim rather than by a fresh interactive challenge
| where AuthenticationRequirement == "multiFactorAuthentication"
    and tostring(AuthenticationDetails) has "previouslySatisfied"
    and (isempty(Device) or Compliant != "true")
| summarize logins = count(), asns = make_set(AutonomousSystemNumber),
            ips = make_set(IPAddress), countries = make_set(Location)
    by UserPrincipalName, AppDisplayName, bin(TimeGenerated, 1h)
| where array_length(asns) > 1
```

**Why `previouslySatisfied` matters.** An AiTM proxy steals the *session cookie*, so
the replayed sign-in shows MFA as already satisfied without a fresh challenge, from an
unenrolled device. That combination is the signal; MFA being present is not protection
against it.

**False positives.** Travel — which during an event window is *guaranteed*. Delegates
legitimately sign in from multiple countries and ASNs within hours. Do not alert on
geography alone; the unenrolled-device plus previously-satisfied-MFA pair is what
carries the detection. Consider suppressing on device-compliant sessions entirely.

**ATT&CK.** T1566 Phishing; T1557 Adversary-in-the-Middle; T1550.004 Web Session
Cookie.

---

### DH-6 — Build-pipeline compromise in event-adjacent software

**Behavior.** Rather than attacking hardened venue infrastructure directly, compromise
a supplier whose code is deployed into it — accreditation systems, scheduling apps,
badge/access control, AV and translation systems, transport integrations.

**Data.** CI/CD audit logs, artifact registry logs, VCS audit events, runner egress
NetFlow.

**Logic — three independent, all cheap:**

1. **Workflow file changed by an account that has never changed it before**, within
   the window, on a repo that deploys to an event-tagged environment.
2. **Build-runner egress to a destination not in the build's declared dependency set.**
   Pin an allowlist per pipeline; alert on first-seen egress domains during a build.
3. **Artifact published without a corresponding green CI run**, or a published digest
   that does not match any digest produced by a recorded build.

```sql
-- Leg 3: artifact/build provenance mismatch
SELECT a.artifact_name, a.digest, a.published_at, a.published_by
FROM artifact_registry_events a
LEFT JOIN ci_build_records b
  ON  b.output_digest = a.digest
  AND b.status = 'success'
WHERE b.output_digest IS NULL
  AND a.published_at BETWEEN (SELECT freeze_start FROM event_window)
                         AND (SELECT freeze_end   FROM event_window)
```

**False positives.** Manual hotfix publishes and registry mirroring. Both should be
rare under freeze and both warrant a look.

**ATT&CK.** T1195.002 Compromise Software Supply Chain; T1554 Compromise Host Software
Binary.

---

### DH-7 — Unauthorized content write to public-facing assets (defacement)

**Behavior.** CMS or object-store write producing attacker-controlled content on a
public site, or HMI screen content replacement on an exposed OT device. Defacement is
the claim mechanism for most hacktivist operations and is intended to be seen.

**Data.** CMS audit logs, object-store (S3/blob) write events, file-integrity
monitoring on web roots, external synthetic monitoring.

**Logic.** Under freeze, *any* write to a production web root or public bucket that
lacks a matching deployment record is an alert. Supplement with an external synthetic
check — fetch the homepage every 60s from an off-network vantage point and diff a
normalized hash of the DOM. This catches compromise paths that bypass your logging
entirely (edge/CDN config takeover, DNS hijack), which is precisely the class your
internal telemetry cannot see.

**ATT&CK.** T1491.002 External Defacement; T0879 Damage to Property (ICS, for HMI cases).

---

## 4. Decoys as a window-scoped control

CISA published *Using Cyber Decoys to Strengthen Detection and Response* on
2026-09-16, directed at critical-infrastructure owners and operators. Decoys are an
unusually good fit for this threat model because archetypes A and B are
**opportunistic** — they take what enumeration returns, without validating it.

Practical deployment, stood up at `T-14d` and removed at `T+7d`:

- A deliberately exposed HMI-alike on a plausible netblock, listening on 20256/5900,
  with credentials that appear default. Any interaction is a high-fidelity alert —
  there is no benign reason to touch it.
- Canary credentials seeded into the accreditation-portal user set. Any authentication
  is a confirmed phish-to-use conversion, and timestamps the capture.
- A honeytoken artifact in the supplier registry. Any pull from outside the build
  plane indicates registry access you did not know about.

Decoys must be **inventoried, isolated, and time-boxed**, with a documented teardown
owner. An undocumented decoy that outlives the window becomes a real exposure and,
worse, a false incident during the next event.

---

## 5. Baselining discipline

The most common failure mode for event-window detection is baselining against the
quiet period, which makes every volume-based rule fire on day one and get disabled by
an exhausted analyst at 03:00.

- Compute per-asset baselines **daily through the window**, not once before it.
- Store baselines per `phase`, not globally.
- Where a prior comparable event exists (last year's summit, previous election),
  baseline against **that event's** profile rather than against last month.
- For any rule with a threshold, record the threshold's provenance in the rule
  metadata. A threshold nobody can justify gets tuned to uselessness within a week.

---

## 6. Validation before the window opens

Detections that have never fired in test do not exist. Run these at `T-21d`:

| Hypothesis | Validation |
|---|---|
| DH-1 | Authorized scan from an external vantage host across the OT port set; confirm alert and fan-out count |
| DH-2 | Stand up a lab VNC with `auth=None` in an OT-tagged range; connect externally |
| DH-3 | Execute an approved program download **outside** a change ticket on a lab PLC; confirm critical alert |
| DH-4 | Load-generate against a staging host with low path entropy and cache-busting query strings |
| DH-5 | Replay a captured session cookie from an unenrolled device in a test tenant |
| DH-6 | Publish an artifact to a staging registry with no matching build record |
| DH-7 | Write to a staging web root outside a deployment window; verify synthetic diff also catches it |

Record MTTD for each. If a rule cannot be validated, it ships as a **hunt query**, not
as an alert — an unvalidated alert rule is a future incident's false sense of security.

---

## 7. Coverage summary

| ID | Hypothesis | Primary telemetry | Confidence | Deploy priority |
|---|---|---|---|---|
| DH-3 | OT config write during freeze | OT protocol sensor | Very high | 1 |
| DH-2 | Weak-auth control-device access | Zeek rfb / OT sensor | Very high | 2 |
| DH-7 | Defacement / unauthorized content write | FIM + synthetic | High | 3 |
| DH-5 | Event-themed AiTM phishing | Entra/Okta sign-ins | High | 4 |
| DH-6 | Build-pipeline compromise | CI/CD + registry audit | Medium-high | 5 |
| DH-4 | L7 flood on event assets | WAF/CDN | Medium | 6 |
| DH-1 | OT port enumeration | Perimeter firewall | Low (hunt) | 7 |

Deploy in priority order. DH-3 and DH-2 together cover the documented
opportunistic-OT-access pattern end to end and cost very little to run.

---

## 8. References

- ENISA, *Threat Landscape 2025* — hacktivism at 79% of recorded EU incidents; DDoS at
  96.2% of hacktivist attacks; public administration at 38% of incidents; DDoS waves
  timed to electoral events; faketivism (CARR/Sandworm, CyberAv3ngers/IRGC);
  Z-Pentest-ecosystem claims against internet-accessible OT management interfaces.
  https://www.enisa.europa.eu/publications/enisa-threat-landscape-2025
- ENISA, *Public administration increasingly targeted by DDoS attacks*.
  https://www.enisa.europa.eu/news/public-administration-increasingly-targeted-by-ddos-attacks
- CISA AA25-343A, *Pro-Russia Hacktivists Conduct Opportunistic Attacks Against US and
  Global Critical Infrastructure* — minimally secured internet-facing VNC to SCADA/HMI.
  https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-343a
- CISA AA23-335A, *IRGC-Affiliated Cyber Actors Exploit PLCs in Multiple Sectors,
  Including US Water and Wastewater Systems Facilities* — Unitronics Vision series.
  https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a
- CISA AA26-097A, *Iranian-Affiliated Cyber Actors Exploit Programmable Logic
  Controllers Across US Critical Infrastructure* (2026-04-07) — OT device targeting,
  IOCs, detection guidance for malicious changes to reusable code modules in Rockwell
  Automation PLC programs.
  https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-097a
- CISA, *Using Cyber Decoys to Strengthen Detection and Response* (2026-09-16).
  https://www.cisa.gov/news-events/news/new-cisa-guidance-helps-critical-infrastructure-detect-observe-and-impede-malicious-cyber-activity
- CISA, *Logging Reference Architecture* (August 2026) — logging capability benchmark;
  written for federal agencies, recommended by CISA for critical-infrastructure and
  SLTT entities.
  https://www.cisa.gov/sites/default/files/2026-09/logging-reference-architecture-508.pdf
- CISA AA26-194A, *Improve Router Hygiene to Protect Against Russian State-Sponsored
  Targeting*.
  https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-194a
- MITRE ATT&CK for ICS — T0812, T0822, T0836, T0843, T0857, T0858, T0879, T0883.
- MITRE ATT&CK Enterprise — T1195.002, T1491.002, T1498, T1499, T1550.004, T1557, T1566.

---

## Appendix A — Watchlists to populate before `STAGE`

| Watchlist | Contents | Owner |
|---|---|---|
| `event_window` | phase boundaries, freeze start/end, approvers | Event security lead |
| `event_window_assets` | hostnames/IPs of event-adjacent public assets | Infra |
| `event_accredited_identities` | UPNs of delegation, secretariat, press, vendor staff | IAM |
| `ot_segments` | CIDRs of OT/DMZ ranges, from asset inventory | OT security |
| `approved_change_requests` | asset_id, window, status — structured, not email | Change management |
| `build_egress_allowlist` | per-pipeline permitted egress domains | Platform |
| `decoy_inventory` | decoy assets, ranges, teardown owner and date | Detection engineering |

Every rule above joins at least one of these. Populating them is the actual work;
the query logic is the easy part.
