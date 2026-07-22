# 🛡️ Report Hub

**A self-contained cyber threat intelligence report generator.** One script, one command, four polished HTML reports — pulled live from free, public threat-intel sources and bundled under a timestamped hub page you can open in any browser.

No database, no framework, no server. Just Python and two small dependencies.

## Reports

| Report | What it covers | Sources |
|---|---|---|
| 🛡️ **Critical CVE Watch** | CVSS > 9 and CISA KEV-confirmed CVEs over the last 7 / 30 / 365 days, ranked by a blended impact score | NVD API, CISA KEV |
| 🏴‍☠️ **Ransomware Watch** | Top threat actors, sectors, and countries hit; high-impact attacks over the last year; freshest victims | ransomware.live |
| 📡 **Cyber News Wire** | Last-24h headlines from 8 major security outlets, plus the week's important stories detected by cross-source coverage | RSS feeds |
| 🎭 **Threat Actor & Breach Watch** | Actively tracked APT groups with their campaigns, TTPs, and tooling; breaches disclosed this week and the year's biggest | MITRE ATT&CK, Have I Been Pwned |

Each run creates a folder like `reports/15JUL26-2033/` containing all four reports plus an `index.html` hub page with links to each one. Every report gets a floating "← Back to Index" button.

## Quick start

```bash
git clone https://github.com/vyshak2000/report-hub.git
cd report-hub
pip install requests feedparser
python cyber_intel_suite.py
```

That's it. The four generators run **concurrently**, the hub page opens in your browser when they finish, and everything works with zero configuration — no API keys required.

## Optional: API keys

Keys aren't required, but an NVD key makes the CVE report dramatically faster (the public NVD rate limit is 5 requests / 30 seconds).

Create an `api_keys.txt` next to the script:

```ini
# Free key: https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY=your-key-here

# Optional (ransomware.live Pro)
RANSOMWARE_LIVE_API_KEY=your-key-here
```

Environment variables with the same names override the file. **Never commit `api_keys.txt`** — it's in `.gitignore`.

## Usage

```bash
python cyber_intel_suite.py                    # run all four reports
python cyber_intel_suite.py --modules cve,news # run a subset (cve, rsw, news, ttp)
python cyber_intel_suite.py --fresh            # ignore caches, re-download everything
python cyber_intel_suite.py --no-browser       # don't auto-open the hub page
```

## How it works

**Concurrent by design.** All four generators run in parallel threads, so total wall time is roughly the slowest module, not the sum of all four. Within modules, independent fetches (RSS feeds, monthly victim pages) are parallelized too.

**Cached where it counts.** Heavy, slow-changing datasets are cached on disk in `cache/` and only re-downloaded when stale — the MITRE ATT&CK bundle (tens of MB) for 7 days, the CISA KEV catalog for 24 hours, the HIBP breach list for 6 hours. If a source is unreachable, a stale cached copy is used rather than dropping the section. Use `--fresh` to force re-downloads.

**Resilient.** Every HTTP call goes through pooled sessions with automatic retry and backoff (429s honor `Retry-After`). NVD requests are properly rate-limited. If a module fails outright, the other three still generate and the hub page marks the failed one.

**Safe rendering.** All external data — victim names, group descriptions, RSS titles, breach descriptions — is HTML-escaped before it touches a report. Much of this data is authored by threat actors; it is never rendered raw.

## Honest scoring

Some rankings in these reports are heuristics, and the reports say so on the page:

- **CVE impact score** blends CVSS, NVD reference volume, press/media-tagged references, and KEV status. It's a ranking aid, not an official severity metric.
- **Ransomware attack "impact"** weighs exposed infostealer record counts, press coverage, and posted incident updates — public-signal volume, not verified damage.
- **"Important" news** means multiple independent outlets covered the same story (matched by shared CVE IDs or named entities), not an official threat rating.
- **APT "activity"** is proxied by how recently MITRE updated a group's ATT&CK entry, since no free feed publishes real-time actor status.

When live data for a section can't be fetched at all, the report falls back to labeled static examples and says so prominently — it never silently presents stale data as current.

## Project structure

```
report-hub/
├── cyber_intel_suite.py   # the whole tool, single file
├── api_keys.txt           # your keys (git-ignored, optional)
├── cache/                 # cached datasets (git-ignored, auto-created)
└── reports/
    └── 15JUL26-2033/      # one folder per run
        ├── index.html
        ├── cve.html
        ├── ransomware.html
        ├── news.html
        └── threat_actors.html
```

Suggested `.gitignore`:

```gitignore
api_keys.txt
cache/
reports/
__pycache__/
```

## Requirements

- Python 3.9+
- `requests`, `feedparser`

## Data sources & credits

This tool only aggregates and presents data generously made public by:

- [NVD](https://nvd.nist.gov/) — National Vulnerability Database (NIST)
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — Known Exploited Vulnerabilities catalog
- [ransomware.live](https://www.ransomware.live/) by Julien Mousqueton
- [MITRE ATT&CK®](https://attack.mitre.org/) — ATT&CK is a registered trademark of The MITRE Corporation
- [Have I Been Pwned](https://haveibeenpwned.com/) by Troy Hunt
- News feeds from BleepingComputer, The Hacker News, Krebs on Security, Dark Reading, SecurityWeek, The Record, Infosecurity Magazine, and Graham Cluley

Please respect each source's terms of use and rate limits.

## Disclaimer

Report Hub is an aggregation and visualization tool for personal and educational use. It makes no guarantees about the accuracy, completeness, or timeliness of upstream data, and its heuristic scores should not be used as the sole basis for security decisions.

## License

MIT — see [LICENSE](LICENSE).
