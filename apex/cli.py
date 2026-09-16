"""Command-line runner for the APEX module.

    python -m apex --status         show which providers are configured
    python -m apex --collect        collect from configured providers (needs keys)
    python -m apex --demo            run offline with bundled sample data

Credentials are read from the environment only (see :mod:`apex.config`). The
``--demo`` mode injects a fake transport with realistic sample payloads so the
whole pipeline can be exercised with no keys and no network.
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys

from .apex import ApexModule
from .config import ProviderConfig, load_config
from .http import HttpClient, HttpResponse
from .security import Secret


def _demo_configs():
    return {
        "huntio": ProviderConfig("huntio", "https://api.hunt.io/v1",
                                 token=Secret("demo-token", "t")),
        "huntress": ProviderConfig("huntress", "https://api.huntress.io/v1",
                                   basic_user=Secret("demo-key", "u"),
                                   basic_pass=Secret("demo-secret", "p")),
    }


def _demo_client_factory(cfg: ProviderConfig) -> HttpClient:
    """A client whose transport returns canned, provider-specific payloads."""
    if cfg.name == "huntio":
        ndjson = (
            b'{"ip":"185.234.72.10","port":443,"malware":"CobaltStrike","confidence":95,'
            b'"first_seen":"2026-09-10T00:00:00Z","actor":"APT-DEMO"}\n'
            b'{"domain":"c2.evil.example","malware":"Emotet","confidence":70}\n'
            b'{"ip":"91.207.12.95","port":8080,"malware":"Sliver","confidence":60}\n'
        )
        body = gzip.compress(ndjson)
        return HttpClient(lambda req: HttpResponse(200, {"Content-Encoding": "gzip"}, body),
                          sleep=lambda d: None)

    # huntress: one page of incident reports, then an empty page.
    pages = [
        json.dumps({"pagination": {"next_page": 2}, "incident_reports": [
            {"id": 5001, "severity": "critical", "status": "sent",
             "summary": "Ransomware precursor blocked", "organization_id": 42,
             "agent_id": 900, "indicators": ["185.234.72.10", "bad.example.org"],
             "created_at": "2026-09-15T18:22:00Z"},
        ]}).encode(),
        json.dumps({"pagination": {"next_page": None}, "incident_reports": []}).encode(),
    ]
    state = {"i": 0}

    def transport(req):
        i = min(state["i"], len(pages) - 1)
        state["i"] += 1
        return HttpResponse(200, {}, pages[i])

    return HttpClient(transport, sleep=lambda d: None)


def cmd_status(env=None) -> int:
    configs = load_config(env)
    if not configs:
        print("No providers configured. Set HUNTIO_API_TOKEN and/or "
              "HUNTRESS_API_KEY + HUNTRESS_API_SECRET.")
        return 0
    for name, cfg in sorted(configs.items()):
        mode = "token" if cfg.token else "basic-auth"
        print(f"  {name:10} {cfg.base_url}  [{mode}, rate={cfg.rate_per_sec}/s]")
    return 0


def cmd_collect(env=None) -> int:
    apex = ApexModule.from_env(env)
    if not apex.providers:
        print("No providers configured; nothing to collect.")
        return 1
    feed = apex.collect()
    print(feed.to_json())
    return 0


def cmd_demo() -> int:
    apex = ApexModule(_demo_configs(), client_factory=_demo_client_factory)
    feed = apex.collect()
    print("APEX demo — offline sample ingest")
    print("=" * 40)
    print(feed.to_json())
    print("\nsummary:", json.dumps(feed.stats()))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="apex", description="Aegis APEX threat-intel integration")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--status", action="store_true", help="list configured providers")
    group.add_argument("--collect", action="store_true", help="collect from live providers")
    group.add_argument("--demo", action="store_true", help="run offline with sample data")
    args = parser.parse_args(argv)

    if args.collect:
        return cmd_collect()
    if args.demo:
        return cmd_demo()
    return cmd_status()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
