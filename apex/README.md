# APEX — Aegis Provider EXchange

APEX is Aegis CyberNet's **threat-intelligence integration layer**. It ingests
indicators and detections from external security providers and normalises them
into one provider-agnostic schema, de-duplicated across sources.

Pure standard library. No third-party dependencies. 45 offline tests.

## Providers

| Provider | Source | API | Yields |
|----------|--------|-----|--------|
| **hunt.io** | C2 Feed of malicious infrastructure | `GET /feeds/c2` (token header, gzip NDJSON) — [docs](https://apidocs.hunt.io/docs/c2-feed) | `Indicator`s |
| **Huntress** | Managed EDR incident reports | `GET /incident_reports` (HTTP Basic, paginated JSON) — [docs](https://api.huntress.io/docs) | `IncidentReport`s (+ embedded `Indicator`s) |

## Architecture

```
 env vars ─▶ config.py ─▶ Secret-wrapped credentials
                 │
                 ▼
        ┌──────────────── ApexModule ────────────────┐
        │  builds one provider per configured vendor   │
        └───────────────────┬──────────────────────────┘
                            │  shared, per-provider
                            ▼  rate-limited HTTP stack
   ┌─────────── http.py (hardened) ───────────┐
   │  TLS-pinned transport · jittered retries · │
   │  token-bucket rate limit · secret redaction│
   └───────────────────┬────────────────────────┘
                       ▼
        providers/huntio.py     providers/huntress.py
          (gzip NDJSON)            (paginated JSON)
                       │
                       ▼  normalise + validate
              models.py (Indicator / IncidentReport)
                       │
                       ▼  de-duplicate across providers
                AggregatedFeed  (JSON out)
```

## Quick start

```bash
# 1. configure credentials (environment only)
export HUNTIO_API_TOKEN=...            # hunt.io
export HUNTRESS_API_KEY=...            # Huntress
export HUNTRESS_API_SECRET=...

# 2. see what's configured
python -m apex --status

# 3. collect and print a normalised, de-duplicated feed
python -m apex --collect

# 4. or run fully offline with bundled sample data (no keys, no network)
python -m apex --demo
```

## Library use

```python
from apex import ApexModule

apex = ApexModule.from_env()          # reads HUNTIO_/HUNTRESS_ env vars
feed = apex.collect(indicator_limit=1000, incident_limit=100)

print(feed.stats())                   # {'indicators': N, 'incidents': M, 'by_type': {...}}
for ind in feed.indicators:
    print(ind.type.value, ind.value, ind.source, ind.confidence.name)

print(feed.to_json())                 # normalised JSON for downstream Aegis consumers
```

## Cross-provider enrichment

When the same indicator arrives from more than one provider it collapses to a
single record: the **strongest** confidence and severity win, malware/actor
attribution is filled in from whichever source has it, tags are unioned, and the
`source` becomes e.g. `huntio+huntress`. This is APEX's core value — a unified,
enriched view instead of N vendor silos.

## Security

APEX handles live API credentials, so it is built defensively: environment-only
secrets wrapped so they never print, mandatory TLS verification, jittered retries
with `Retry-After`, token-bucket rate limiting, defensive response parsing, and
per-provider fault isolation. See [`../SECURITY.md`](../SECURITY.md) for the full
security structure.

## Extending

Add a provider by subclassing `apex.providers.base.Provider`, setting
`supports_indicators` / `supports_incidents`, implementing `fetch_*`, and
registering it in `apex/apex.py::_PROVIDERS` plus `apex/config.py`.

## Tests

```bash
python -m unittest discover -s tests -p "test_apex_*.py" -v
```
