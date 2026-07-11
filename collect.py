#!/usr/bin/env python3
#
# OnionHop SNI Collector
# Copyright (C) 2026 center2055
#
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU
# Affero General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version. Distributed WITHOUT ANY WARRANTY. See the GNU AGPL
# v3 (the LICENSE file) for details.
"""
OnionHop SNI Collector
======================

Builds the per-country SNI / front-domain candidate lists that the OnionHop app fetches behind its
"Request SNI" button, and refreshes them automatically (daily in CI). It mirrors the OnionHop bridge
collector's shape - assemble candidates, test, publish - but SNI is different from bridges in one
important way, and the design reflects it:

    A bridge that is up is up globally, so a cloud runner's reachability test is valid everywhere.
    An SNI's value is whether it is UNBLOCKED IN THE TARGET COUNTRY, and a censor's SNI blocklist
    cannot be measured from outside that country. So this collector does NOT claim to know what is
    unblocked in Iran or Turkmenistan. It produces good *candidates* per country; the per-network
    verdict is made on the user's own device by the app's SNI scanner (which TLS-probes each
    candidate and keeps the ones that work on that network).

What the collector actually does:

  * Candidate sources (per country):
      - a curated GLOBAL pool of large HTTPS hosts (pool.txt) - strong camouflage almost everywhere
        because blocking them carries heavy collateral - added to every country as a baseline;
      - per-country DOMESTIC seeds (seeds/<code>.txt) - popular in-country hosts that make the best
        local camouflage. Maintainer-curated; drop a file in to add or extend a country.
  * Testing (liveness only, from the runner - NOT a censorship verdict):
      - pool/global candidates are TLS-tested (they are global by nature, so a runner test is valid);
        entries that no longer complete a TLS handshake are dropped.
      - domestic seeds are only pruned when they no longer RESOLVE (a geo-agnostic "domain is gone"
        signal). A seed that resolves but is unreachable from the runner is KEPT, because it may be
        geo-restricted yet perfect inside its own country - exactly the case a runner cannot judge.
  * Publish: sni/<code>.txt (one domain per line, sorted) + index.json (code, name, file, count) -
      the exact layout SniListSource in the app already fetches, so nothing on the client changes.

Later tiers can enrich candidates/ranking with per-country signals (Cloudflare Radar top domains,
OONI blocking measurements) without changing this output format. Standard library only.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import socket
import ssl

# --- Configuration ----------------------------------------------------------

SNI_DIR = "sni"
SEEDS_DIR = "seeds"
POOL_FILE = "pool.txt"
INDEX_FILE = "index.json"

PORT = 443
CONNECT_TIMEOUT = 8
TLS_ATTEMPTS = 2  # retry once so a transient runner hiccup does not flap a good host in/out
MAX_WORKERS = 40

INDEX_NOTE = (
    "Per-country SNI/front-domain candidate lists for OnionHop's SNI scanner. Each entry points to "
    "sni/<code>.txt (one domain per line). Scan these with the app/VPN OFF to find which SNIs work "
    "on your network, then apply the working ones as custom SNI hosts. Lists are refreshed "
    "automatically; the per-network verdict is made on your device, not by the collector."
)

# Countries to publish. The global pool applies to every country; seeds/<code>.txt adds domestic
# candidates. To add a country: add it here (and, ideally, a seeds/<code>.txt of local hosts).
COUNTRIES = {
    "ir": "Iran",
    "cn": "China",
    "ru": "Russia",
    "tm": "Turkmenistan",
}


def log(message: str) -> None:
    print(message, flush=True)


# --- Candidate loading ------------------------------------------------------

def normalize(entry: str) -> str:
    """Reduce an entry to a bare lower-case host: strip scheme, path, port and a trailing dot."""
    value = entry.strip()
    if not value or value.startswith("#"):
        return ""
    scheme = value.find("://")
    if scheme >= 0:
        value = value[scheme + 3:]
    for sep in ("/", "?", "#"):
        cut = value.find(sep)
        if cut >= 0:
            value = value[:cut]
    # Strip a trailing :port (but leave bracketed IPv6 literals alone - hosts here are domains).
    if value.count(":") == 1:
        head, _, tail = value.partition(":")
        if tail.isdigit():
            value = head
    return value.strip().strip(".").lower()


def read_domains(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    seen: set[str] = set()
    out: list[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            host = normalize(raw)
            if host and host not in seen:
                seen.add(host)
                out.append(host)
    return out


# --- Testing ----------------------------------------------------------------

def resolves(domain: str) -> bool:
    """True if the domain has any A/AAAA record (a geo-agnostic 'still exists' check)."""
    try:
        socket.getaddrinfo(domain, PORT, proto=socket.IPPROTO_TCP)
        return True
    except OSError:
        return False


def tls_ok(domain: str) -> bool:
    """True if a TLS handshake to domain:443 completes, using the domain as SNI (cert not verified -
    a completed handshake is the reachability signal we want)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for attempt in range(TLS_ATTEMPTS):
        try:
            with socket.create_connection((domain, PORT), timeout=CONNECT_TIMEOUT) as raw:
                with ctx.wrap_socket(raw, server_hostname=domain):
                    return True
        except (OSError, ssl.SSLError):
            if attempt == TLS_ATTEMPTS - 1:
                return False
    return False


def test_many(domains: list[str], predicate) -> set[str]:
    if not domains:
        return set()
    passing: set[str] = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(domains))) as pool:
        futures = {pool.submit(predicate, d): d for d in domains}
        for future in concurrent.futures.as_completed(futures):
            try:
                if future.result():
                    passing.add(futures[future])
            except Exception:  # noqa: BLE001 - one probe must never kill the run
                pass
    return passing


# --- Persistence ------------------------------------------------------------

def write_list(path: str, domains) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        for domain in sorted(domains):
            handle.write(domain + "\n")


def write_index(entries: list[dict]) -> None:
    payload = {"version": 1, "note": INDEX_NOTE, "countries": entries}
    with open(INDEX_FILE, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


# --- Main -------------------------------------------------------------------

def main() -> None:
    os.makedirs(SNI_DIR, exist_ok=True)

    pool = read_domains(POOL_FILE)
    log(f"Global pool: {len(pool)} candidates; TLS-testing...")
    pool_alive = test_many(pool, tls_ok)
    log(f"Global pool: {len(pool_alive)}/{len(pool)} reachable.")

    entries: list[dict] = []
    for code, name in COUNTRIES.items():
        seeds = read_domains(os.path.join(SEEDS_DIR, f"{code}.txt"))
        # Domestic seeds: prune only DNS-dead (a runner cannot judge in-country reachability).
        seeds_alive = test_many(seeds, resolves) if seeds else set()
        combined = sorted(pool_alive | seeds_alive)

        file_name = f"{SNI_DIR}/{code}.txt"
        write_list(file_name, combined)
        entries.append({"code": code, "name": name, "file": file_name, "count": len(combined)})
        log(f"{code} ({name}): {len(combined)} candidates "
            f"(pool {len(pool_alive)} + domestic {len(seeds_alive)}/{len(seeds)} resolvable).")

    write_index(entries)
    log(f"Wrote {INDEX_FILE} with {len(entries)} countries.")


if __name__ == "__main__":
    main()
