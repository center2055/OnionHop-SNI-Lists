# OnionHop SNI Lists

Per-country **SNI / front-domain candidate lists** for the OnionHop SNI scanner, refreshed
automatically by a small collector (`collect.py`, run daily in CI).

Working SNI hosts (the domains a censoring network doesn't block on TLS) are **country-specific** —
what works in one country often doesn't in another. This repo publishes candidate domains per
country; OnionHop's **SNI Scanner** fetches the list for your country ("Request SNI"), TLS-probes
each one, and lets you apply the ones that work as your custom SNI / front hosts for fronted bridges
(webtunnel / meek / snowflake).

## Bridges are global, SNIs are local

A bridge that is up is up everywhere, so a cloud test of it is valid everywhere. An SNI is different:
its value is whether it is **unblocked in your country**, and a censor's SNI blocklist can't be
measured from outside that country. So this collector does **not** claim to know what is unblocked in
Iran or Turkmenistan. It produces good **candidates** per country; the **per-network verdict is made
on your own device** by the app's SNI scanner. That is also the most accurate place for it, since SNI
blocking varies by ISP, not just by country.

## Layout

Generated (fetched by the app — do not edit by hand):

- [`index.json`](index.json) — the available countries and where to find each file.
- `sni/<code>.txt` — one candidate domain per line for ISO 3166-1 alpha-2 code `<code>`
  (e.g. [`sni/tm.txt`](sni/tm.txt) for Turkmenistan).

Sources (edit these):

- [`pool.txt`](pool.txt) — a curated **global** pool of large HTTPS hosts (major CDNs, cloud, popular
  sites) that make good camouflage almost everywhere. Added to every country as a baseline.
- `seeds/<code>.txt` — per-country **domestic** candidates (popular in-country hosts). The best local
  camouflage; maintainer-curated.
- [`collect.py`](collect.py) — assembles pool + seeds per country, tests them, and writes the
  generated files. It TLS-tests the global pool (drops globally-dead hosts) and only prunes a
  domestic seed when it no longer resolves (a runner can't judge in-country reachability, so a
  resolving-but-geo-restricted seed is kept).

## How the app uses it

The scanner reads `index.json` to populate the country picker, fetches `sni/<code>.txt` for the
chosen country, and scans those domains. **Run the scan with the app/VPN switched off**, so you are
testing your real network, not a Tor exit. Apply the green (working) ones as your custom SNI hosts.

## Contributing

- **Add/extend a country:** drop or edit `seeds/<code>.txt` (one domain per line; `#` comments ok)
  and add the country to `COUNTRIES` in `collect.py`. Good domestic candidates are large, widely-used
  in-country HTTPS sites that would be costly for a censor to block.
- **Improve the global baseline:** edit `pool.txt`.
- The generated `sni/` and `index.json` are rebuilt on the next run, so you don't edit them directly.

Future enrichment (not yet wired): per-country candidate discovery and blocked/reachable ranking from
open sources such as Cloudflare Radar top-domains and OONI measurements, which would add real
in-country signal without changing this output format.
