# Security Structure — Aegis CyberNet

This document describes the security posture of the Python modules in this
repository, with emphasis on the **APEX** threat-intelligence integration layer,
which handles third-party API credentials and talks to the public internet.

## 1. Secret handling

- **Environment-only credentials.** API keys are read exclusively from process
  environment variables (`apex/config.py`). No key is ever a source-code
  default, and no `.env` with real values is committed (`.env` is git-ignored;
  only `.env.example` — names, no values — is tracked).
- **Opaque `Secret` wrapper.** Every credential is wrapped in
  `apex.security.Secret`. Its `__repr__`/`__str__` render `***REDACTED***`, so a
  secret cannot reach a log line, f-string, or traceback frame by accident. The
  raw value is available only via an explicit `.reveal()` at the point it is
  handed to the transport.
- **Constant-time comparison.** `Secret.__eq__` uses `hmac.compare_digest` to
  avoid leaking information through timing.
- **Error redaction.** Before any transport error is raised, its text is passed
  through `apex.security.redact(...)`, which masks known secret values — so a URL
  or header that carried a token never surfaces in an exception.

## 2. Transport security

- **TLS verification is mandatory.** `apex.security.hardened_ssl_context()`
  pins `check_hostname=True`, `CERT_REQUIRED`, and a TLS 1.2 floor. There is no
  switch to disable verification — an insecure downgrade is impossible by
  construction.
- **Explicit timeouts** on every request; no unbounded hangs.
- **Bounded, jittered retries.** Only idempotent methods (`GET`/`HEAD`) retry,
  only on connection errors and HTTP 429/5xx, capped by `max_retries`, using
  full-jitter exponential backoff and honouring `Retry-After`.
- **Rate limiting.** A monotonic token-bucket (`apex/ratelimit.py`) gates every
  request to stay within provider quotas.

## 3. Input / response handling

- **Defensive parsing.** Provider responses are treated as untrusted: malformed
  NDJSON lines and bad records are dropped, not trusted; JSON envelopes are
  shape-checked before use. A single bad record never aborts an ingest.
- **Normalisation boundary.** External payloads are converted into the internal
  `Indicator` / `IncidentReport` models, which validate their own invariants,
  before any downstream code sees them.

## 4. Fault isolation

- **Per-provider isolation.** In `ApexModule.collect()`, a failing provider is
  caught and recorded in `feed.errors`; other providers still contribute. One
  vendor outage cannot take down the whole ingest.
- **Injectable transport.** The network layer is an injectable callable, so the
  entire stack is unit-tested (80 tests) with **zero real network access** — no
  live credentials or endpoints are needed to validate behaviour.

## 5. Least privilege & responsible use

- Use **read-only** API scopes/tokens for both providers; APEX only performs
  `GET` reads of feeds and reports.
- Rotate provider tokens regularly and scope them to the minimum needed.
- This tooling is for **authorized defensive security operations** (threat
  intelligence ingestion for a SOC). It ingests and normalises vendor data; it
  performs no offensive action.

## Reporting

For sensitive security concerns about this repository, contact the maintainer
privately rather than opening a public issue.
