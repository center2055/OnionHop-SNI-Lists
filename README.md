# OnionHop SNI Lists

Per-country **SNI / front-domain candidate lists** for the OnionHop SNI scanner.

Working SNI hosts (the domains a censoring network doesn't block on TLS) are **country-specific** —
what works in one country often doesn't in another. This repo publishes a starter list of candidate
domains per country; OnionHop's **SNI Scanner** can fetch the list for your country ("Request SNI"),
TLS-probe each one, and let you apply the ones that work as your custom SNI / front hosts for
fronted bridges (webtunnel / meek / snowflake).

## Layout

- [`index.json`](index.json) — the list of available countries and where to find each file.
- `sni/<code>.txt` — one candidate domain per line, for ISO 3166-1 alpha-2 country code `<code>`
  (e.g. [`sni/tm.txt`](sni/tm.txt) for Turkmenistan). Lines starting with `#` are ignored.

## How the app uses it

The scanner reads `index.json` to populate the country list, then fetches
`sni/<code>.txt` for the chosen country and scans those domains. **Run the scan with the app/VPN
switched off**, so you're testing your real network, not a Tor exit.

## Contributing a country

Add `sni/<code>.txt` with candidate domains (one per line) and a matching entry in `index.json`.
Good candidates are large, widely-used HTTPS domains that are reachable in that country.
