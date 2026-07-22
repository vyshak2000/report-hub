#!/usr/bin/env python3
"""
Cyber Intel Suite v2 - Report Hub
=================================
Generates four HTML reports into a timestamped folder under reports/,
plus an index.html hub page:

  -> index.html          (Home Page)
  -> cve.html            (Critical CVE Watch)
  -> ransomware.html     (Ransomware Watch)
  -> news.html           (Cyber News Wire)
  -> threat_actors.html  (Threat Actor & Breach Watch)

Config files (next to this script):
  api_keys.txt   one KEY=VALUE per line, '#' comments allowed. Recognized:
                   NVD_API_KEY=...             (raises NVD rate limit a lot)
                   RANSOMWARE_LIVE_API_KEY=... (optional)
                 Environment variables of the same name override the file.

Usage:
  python cyber_intel_suite.py                 # run everything
  python cyber_intel_suite.py --modules cve,news
  python cyber_intel_suite.py --fresh --no-browser
"""

import argparse
import calendar
import html as html_lib
import json
import os
import re
import threading
import time
import webbrowser
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path

import feedparser
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Paths / run folder
# ---------------------------------------------------------------------------

try:
    SCRIPT_DIR = Path(__file__).resolve().parent
except NameError:  # e.g. pasted into a REPL
    SCRIPT_DIR = Path.cwd()

RUN_TIMESTAMP = datetime.now().strftime("%d%b%y-%H%M").upper()  # 15JUL26-2033
RUN_DIR = SCRIPT_DIR / "reports" / RUN_TIMESTAMP
CACHE_DIR = SCRIPT_DIR / "cache"

FORCE_FRESH = False  # set by --fresh; cached_json() checks it

USER_AGENT = "cyber-intel-suite/2.0"


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------

def load_api_keys(filename="api_keys.txt"):
    path = SCRIPT_DIR / filename
    keys = {}
    if not path.exists():
        return keys
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key.strip():
            keys[key.strip()] = value.strip()
    return keys


API_KEYS = load_api_keys()


def get_key(name):
    """Env var wins over api_keys.txt."""
    return os.environ.get(name, API_KEYS.get(name, ""))


REPORTS = [
    # key,    filename,             title,                         accent,    blurb
    ("cve",  "cve.html",           "Critical CVE Watch",          "#3b82f6",
     "CVSS>9 and KEV-confirmed CVEs, last 7/30/365 days."),
    ("rsw",  "ransomware.html",    "Ransomware Watch",            "#f43f5e",
     "Threat actors, sectors, countries, and high-impact attacks."),
    ("news", "news.html",          "Cyber News Wire",             "#14b8a6",
     "Last 24h headlines plus cross-source important stories."),
    ("ttp",  "threat_actors.html", "Threat Actor & Breach Watch", "#a855f7",
     "APT groups, campaigns, TTPs, and recent/yearly breaches."),
]


# ---------------------------------------------------------------------------
# Small shared utilities
# ---------------------------------------------------------------------------

TAG_RE = re.compile(r"<[^>]+>")


def esc(value):
    """HTML-escape any external value before it touches a report.

    Everything rendered into the reports comes from feeds that adversaries
    can influence (leak sites, RSS, breach descriptions), so escaping at
    the render boundary is non-negotiable."""
    return html_lib.escape(str(value), quote=True)


def strip_tags(raw):
    """Remove HTML tags and decode entities from feed/API text."""
    text = TAG_RE.sub(" ", raw or "")
    text = html_lib.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def truncate(text, max_chars):
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 1].rstrip() + "\u2026"


def rank_label(i):
    medals = ("\U0001f947", "\U0001f948", "\U0001f949")  # gold/silver/bronze
    return medals[i] if i < 3 else f"#{i + 1}"


def make_session(pool_size=8, retries=3, backoff=1.5, extra_headers=None):
    """Session with pooling + automatic retry/backoff (respects Retry-After)."""
    session = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=pool_size,
                          pool_maxsize=pool_size)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({"User-Agent": USER_AGENT})
    if extra_headers:
        session.headers.update(extra_headers)
    return session


class RateLimiter:
    """Enforces a minimum interval between calls. Unlike a blanket
    sleep-after-every-request, this only waits as long as actually needed,
    and never wastes time after the final request."""

    def __init__(self, min_interval):
        self.min_interval = min_interval
        self._last = 0.0
        self._lock = threading.Lock()

    def wait(self):
        with self._lock:
            now = time.monotonic()
            remaining = self.min_interval - (now - self._last)
            if remaining > 0:
                time.sleep(remaining)
            self._last = time.monotonic()


def cached_json(session, url, cache_name, max_age_hours, log, timeout=60):
    """GET url as JSON with an on-disk cache.

    - Serves the cached copy if younger than max_age_hours (unless --fresh).
    - On network failure, falls back to a stale cached copy rather than
      returning nothing.
    """
    path = CACHE_DIR / cache_name

    if not FORCE_FRESH and path.exists():
        age_h = (time.time() - path.stat().st_mtime) / 3600
        if age_h < max_age_hours:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                log(f"  Using cached {cache_name} ({age_h:.1f}h old).")
                return data
            except (json.JSONDecodeError, OSError):
                pass  # corrupt cache -> refetch

    try:
        resp = session.get(url, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        try:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(resp.text, encoding="utf-8")
            tmp.replace(path)  # atomic-ish swap so a crash can't corrupt it
        except OSError as e:
            log(f"  ! Could not write cache {cache_name}: {e}")
        return data
    except Exception as e:
        log(f"  ! Fetch failed for {url}: {e}")
        if path.exists():
            log(f"    Falling back to stale cached {cache_name}.")
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        return None


# ---------------------------------------------------------------------------
# Shared HTML: one stylesheet, four themes
# ---------------------------------------------------------------------------
# v1 duplicated ~600 lines of near-identical CSS across the four reports.
# All components now live in one sheet; each report only supplies its
# color variables. Unused rules in a given report are harmless.

THEMES = {
    "cve": {
        "bg": "#050810", "surface": "#0d1524", "surface_hover": "#131c30",
        "border": "#1d2a44", "text": "#eef3fb", "text_dim": "#8ea0b8",
        "accent": "#3b82f6", "accent_2": "#fb923c",
        "glow_1": "#3b82f622", "glow_2": "#06b6d41c",
    },
    "rsw": {
        "bg": "#0a0508", "surface": "#17101a", "surface_hover": "#1f1620",
        "border": "#2e1f2c", "text": "#f5eef2", "text_dim": "#9c8a97",
        "accent": "#f43f5e", "accent_2": "#fb923c",
        "glow_1": "#f43f5e22", "glow_2": "#7c3aed22",
    },
    "news": {
        "bg": "#050b0a", "surface": "#0e1a18", "surface_hover": "#142523",
        "border": "#1e2f2c", "text": "#eef7f5", "text_dim": "#8aa39c",
        "accent": "#14b8a6", "accent_2": "#6366f1",
        "glow_1": "#14b8a622", "glow_2": "#6366f11c",
    },
    "ttp": {
        "bg": "#0a0713", "surface": "#161129", "surface_hover": "#1c1633",
        "border": "#2a2147", "text": "#f2eefb", "text_dim": "#9c92b8",
        "accent": "#a855f7", "accent_2": "#ec4899",
        "glow_1": "#a855f722", "glow_2": "#ec489922",
    },
    "hub": {
        "bg": "#060608", "surface": "#121016", "surface_hover": "#18151d",
        "border": "#262230", "text": "#f2f0f5", "text_dim": "#948da3",
        "accent": "#3b82f6", "accent_2": "#f43f5e",
        "glow_1": "#3b82f622", "glow_2": "#f43f5e1c",
    },
}

# Note: doubled braces are literal CSS braces; this string is .format()ed
# only for the theme variables.
SHARED_CSS = """
:root {{
  --bg: {bg};
  --surface: {surface};
  --surface-hover: {surface_hover};
  --border: {border};
  --text: {text};
  --text-dim: {text_dim};
  --accent: {accent};
  --accent-2: {accent_2};
  --glow-1: {glow_1};
  --glow-2: {glow_2};
}}

* {{ box-sizing: border-box; }}

body {{
  background:
    radial-gradient(circle at 10% 0%, var(--glow-1) 0%, transparent 45%),
    radial-gradient(circle at 90% 12%, var(--glow-2) 0%, transparent 40%),
    var(--bg);
  color: var(--text);
  font-family: 'Inter', sans-serif;
  margin: 0;
  padding: 48px 24px;
}}

.container {{ max-width: 1200px; margin: auto; }}

.header {{ text-align: center; margin-bottom: 48px; }}
.header .eyebrow {{
  font-family: 'JetBrains Mono', monospace; color: var(--accent);
  letter-spacing: 3px; font-size: 12px; text-transform: uppercase;
  margin-bottom: 12px;
}}
.header h1 {{ font-size: 46px; font-weight: 800; margin: 0 0 8px 0; letter-spacing: -1px; }}
.header p {{ color: var(--text-dim); font-family: 'JetBrains Mono', monospace; font-size: 13px; }}

.grid {{
  display: grid; grid-template-columns: repeat(4, 1fr);
  gap: 16px; margin-bottom: 56px;
}}

.card {{
  background: var(--surface); border: 1px solid var(--border);
  padding: 24px; border-radius: 16px; text-align: center;
  transition: transform .2s ease, border-color .2s ease;
}}
.card:hover {{ transform: translateY(-3px); border-color: var(--accent); }}
.card .label {{ font-size: 13px; color: var(--text-dim); font-weight: 500; margin-bottom: 10px; }}
.card .value {{
  font-size: 36px; font-weight: 800;
  font-family: 'JetBrains Mono', monospace; color: var(--accent);
}}

.section {{ margin-top: 52px; }}
.section-title {{ display: flex; align-items: center; gap: 12px; margin-bottom: 24px; flex-wrap: wrap; }}
.section-title h2 {{
  font-size: 22px; font-weight: 700; margin: 0;
  border-left: 4px solid var(--accent); padding-left: 14px;
}}
.section-title .count {{
  font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--text-dim);
  background: var(--surface); border: 1px solid var(--border);
  padding: 3px 10px; border-radius: 20px;
}}
.section-note {{
  font-family: 'JetBrains Mono', monospace; font-size: 11.5px; color: var(--text-dim);
  margin: -14px 0 20px 0; line-height: 1.6;
}}
.section-warning {{ color: var(--accent-2); }}

/* Ranked cards (CVEs, actors, attacks, important stories) */

.actor-card {{
  display: flex; gap: 18px; align-items: flex-start;
  background: var(--surface); border: 1px solid var(--border);
  border-left: 3px solid var(--accent);
  padding: 20px 24px; margin: 14px 0; border-radius: 12px;
  transition: background .2s ease;
}}
.actor-card:hover {{ background: var(--surface-hover); }}
.actor-card.alt {{ border-left-color: var(--accent-2); }}
.actor-rank {{
  font-size: 22px; font-family: 'JetBrains Mono', monospace; min-width: 36px;
  text-align: center; color: var(--accent-2); font-weight: 700;
}}
.actor-body {{ flex: 1; }}
.actor-top {{
  display: flex; justify-content: space-between; align-items: baseline;
  flex-wrap: wrap; gap: 8px;
}}
.actor-name {{
  font-size: 17px; font-weight: 700;
  font-family: 'JetBrains Mono', monospace; letter-spacing: 0.5px;
}}
.actor-name.caps {{ text-transform: uppercase; }}
.actor-name.plain {{ font-family: 'Inter', sans-serif; letter-spacing: normal; }}
.actor-count {{
  font-family: 'JetBrains Mono', monospace; font-size: 20px; font-weight: 800;
  color: var(--accent); white-space: nowrap;
}}
.actor-card.alt .actor-count {{ color: var(--accent-2); }}
.actor-count span {{
  font-size: 11px; color: var(--text-dim); font-weight: 500; text-transform: uppercase;
}}
.actor-desc {{ font-size: 13.5px; color: var(--text-dim); line-height: 1.6; margin: 8px 0 10px 0; }}
.actor-meta {{
  font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--text-dim);
  display: flex; gap: 14px; flex-wrap: wrap;
}}
.actor-meta.warm {{ color: var(--accent-2); }}

/* Bar charts */

.bar-row {{
  display: grid; grid-template-columns: 160px 1fr 50px;
  align-items: center; gap: 14px; margin: 12px 0;
}}
.bar-label {{
  font-size: 13px; color: var(--text); font-weight: 500;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}}
.bar-track {{
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 8px; height: 14px; overflow: hidden;
}}
.bar-fill {{ height: 100%; border-radius: 8px 0 0 8px; transition: width .3s ease; }}
.bar-count {{
  font-family: 'JetBrains Mono', monospace; font-size: 13px;
  color: var(--text-dim); text-align: right;
}}

/* Victim list */

.victim-row {{
  background: var(--surface); border: 1px solid var(--border);
  padding: 16px 22px; margin: 10px 0; border-radius: 12px;
  display: flex; justify-content: space-between; align-items: center;
  flex-wrap: wrap; gap: 10px; transition: background .2s ease;
}}
.victim-row:hover {{ background: var(--surface-hover); }}
.victim-main {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
.victim-name {{ font-size: 15px; font-weight: 600; }}
.victim-group {{
  font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--accent);
  background: color-mix(in srgb, var(--accent) 10%, transparent);
  border: 1px solid color-mix(in srgb, var(--accent) 28%, transparent);
  padding: 3px 10px; border-radius: 20px; text-transform: uppercase;
}}
.victim-meta {{
  display: flex; gap: 16px;
  font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--text-dim);
}}

/* News list */

.news-item {{
  background: var(--surface); border: 1px solid var(--border);
  border-left: 3px solid var(--accent);
  padding: 18px 24px; margin: 12px 0; border-radius: 12px;
  transition: background .2s ease;
}}
.news-item:hover {{ background: var(--surface-hover); }}
.news-top {{
  display: flex; justify-content: space-between; align-items: flex-start;
  gap: 12px; flex-wrap: wrap; margin-bottom: 8px;
}}
.news-title {{
  font-size: 15.5px; font-weight: 600; color: var(--text);
  text-decoration: none; line-height: 1.4;
}}
.news-title:hover {{ color: var(--accent); }}
.news-desc {{ font-size: 13.5px; color: var(--text-dim); line-height: 1.6; margin: 6px 0 10px 0; }}
.news-meta {{
  display: flex; justify-content: space-between; align-items: center;
  flex-wrap: wrap; gap: 10px;
  font-family: 'JetBrains Mono', monospace; font-size: 11.5px; color: var(--text-dim);
}}
.news-meta a {{ color: var(--accent); text-decoration: none; }}
.news-meta a:hover {{ text-decoration: underline; }}

.source-chips {{ display: flex; gap: 8px; flex-wrap: wrap; }}
.source-chip {{ text-decoration: none; }}

.badge {{
  font-family: 'JetBrains Mono', monospace; font-size: 11px; font-weight: 600;
  padding: 3px 10px; border-radius: 20px; white-space: nowrap;
  background: var(--surface); border: 1px solid var(--border); color: var(--text-dim);
}}
.badge-verified {{ background: #4ade8022; color: #4ade80; border-color: #4ade8055; }}
.badge-unverified {{ background: #64748b22; color: #94a3b8; border-color: #64748b55; }}
.badge-sensitive {{ background: #f43f5e22; color: #f43f5e; border-color: #f43f5e55; }}

/* APT cards */

.apt-card {{
  background: var(--surface); border: 1px solid var(--border);
  border-left: 3px solid var(--accent);
  padding: 22px 26px; margin: 16px 0; border-radius: 14px;
  transition: background .2s ease;
}}
.apt-card:hover {{ background: var(--surface-hover); }}
.apt-card.row {{ display: flex; gap: 16px; align-items: flex-start; }}
.apt-body {{ flex: 1; }}
.apt-top {{
  display: flex; justify-content: space-between; align-items: flex-start;
  gap: 12px; flex-wrap: wrap;
}}
.apt-name {{
  font-size: 19px; font-weight: 800;
  font-family: 'JetBrains Mono', monospace; letter-spacing: 0.3px;
}}
.apt-name.plain {{ font-family: 'Inter', sans-serif; letter-spacing: normal; font-size: 17px; }}
.apt-name a {{ color: var(--text); text-decoration: none; }}
.apt-name a:hover {{ color: var(--accent); }}
.apt-badges {{ display: flex; gap: 8px; flex-wrap: wrap; }}
.aka {{ font-size: 12px; color: var(--text-dim); font-style: italic; margin-top: 4px; }}
.apt-desc {{ font-size: 14px; color: var(--text-dim); line-height: 1.65; margin: 12px 0; }}
.apt-subsection {{ margin-top: 16px; }}
.apt-subtitle {{
  font-family: 'JetBrains Mono', monospace; font-size: 11.5px; text-transform: uppercase;
  letter-spacing: 0.5px; color: var(--accent-2); margin-bottom: 8px; font-weight: 700;
}}
.domain-note {{ color: var(--text-dim); font-weight: 500; font-size: 13px; }}

.chip-list {{ display: flex; flex-wrap: wrap; gap: 6px; }}
.chip {{
  font-family: 'JetBrains Mono', monospace; font-size: 11px; font-weight: 500;
  background: color-mix(in srgb, var(--accent) 10%, transparent);
  color: var(--accent);
  border: 1px solid color-mix(in srgb, var(--accent) 33%, transparent);
  padding: 4px 10px; border-radius: 20px; white-space: nowrap;
}}
.chip-alt {{
  background: color-mix(in srgb, var(--accent-2) 10%, transparent);
  color: var(--accent-2);
  border-color: color-mix(in srgb, var(--accent-2) 33%, transparent);
}}
.chip-muted {{ background: transparent; color: var(--text-dim); border: 1px dashed var(--border); }}

.campaign-list {{ display: flex; flex-direction: column; gap: 8px; }}
.campaign-item {{
  background: rgba(255,255,255,0.02); border: 1px solid var(--border);
  border-radius: 10px; padding: 10px 14px;
}}
.campaign-name {{ font-size: 13.5px; font-weight: 600; }}
.campaign-dates {{
  font-family: 'JetBrains Mono', monospace; font-size: 11px;
  color: var(--text-dim); margin-top: 3px;
}}
.campaign-desc {{ font-size: 12.5px; color: var(--text-dim); margin-top: 5px; line-height: 1.5; }}
.campaign-informal .campaign-name {{ color: var(--text-dim); }}

.breach-meta {{
  display: flex; gap: 20px; flex-wrap: wrap; margin-top: 10px;
  font-family: 'JetBrains Mono', monospace; font-size: 11.5px; color: var(--text-dim);
}}

/* Hub index */

.report-card {{
  display: block; background: var(--surface); border: 1px solid var(--border);
  border-left: 4px solid; border-radius: 16px; padding: 28px; text-decoration: none;
  transition: transform .2s ease, background .2s ease;
}}
.report-card:hover {{ transform: translateY(-4px); background: var(--surface-hover); }}
.report-card-disabled {{ opacity: 0.55; cursor: not-allowed; }}
.report-title {{
  font-size: 19px; font-weight: 800;
  font-family: 'JetBrains Mono', monospace; margin-bottom: 10px;
}}
.report-blurb {{ font-size: 13.5px; color: var(--text-dim); line-height: 1.6; margin-bottom: 18px; }}
.report-cta {{ font-family: 'JetBrains Mono', monospace; font-size: 12px; font-weight: 700; }}
.report-cta-error {{ color: #fb923c; font-weight: 500; }}
.hub-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; }}

.empty-state {{
  color: var(--text-dim); font-family: 'JetBrains Mono', monospace; font-size: 13px;
  padding: 20px; text-align: center; border: 1px dashed var(--border); border-radius: 12px;
}}

.footer {{
  margin-top: 72px; text-align: center; color: var(--text-dim);
  font-family: 'JetBrains Mono', monospace; font-size: 12px;
  border-top: 1px solid var(--border); padding-top: 24px;
}}

@media (max-width: 900px) {{
  .grid {{ grid-template-columns: repeat(2, 1fr); }}
  .header h1 {{ font-size: 32px; }}
  .bar-row {{ grid-template-columns: 110px 1fr 40px; }}
  .hub-grid {{ grid-template-columns: 1fr; }}
}}
"""

FONTS_LINK = (
    '<link href="https://fonts.googleapis.com/css2'
    '?family=Inter:wght@300;400;500;600;700;800'
    '&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">'
)


def render_page(theme_key, page_title, eyebrow, heading, subtitle, body_html,
                footer_html, container_max=1200):
    css = SHARED_CSS.format(**THEMES[theme_key])
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{page_title}</title>
{FONTS_LINK}
<style>{css}
.container {{ max-width: {container_max}px; }}</style>
</head>
<body>
<div class="container">

  <div class="header">
    <div class="eyebrow">{eyebrow}</div>
    <h1>{heading}</h1>
    <p>{subtitle}</p>
  </div>

{body_html}

  <div class="footer">{footer_html}</div>

</div>
</body>
</html>
"""


def stat_grid(stats):
    """stats: iterable of (label, value_html, optional_value_style)."""
    cards = []
    for item in stats:
        label, value = item[0], item[1]
        style = f' style="{item[2]}"' if len(item) > 2 and item[2] else ""
        cards.append(
            f'    <div class="card">\n'
            f'      <div class="label">{label}</div>\n'
            f'      <div class="value"{style}>{value}</div>\n'
            f'    </div>'
        )
    return '  <div class="grid">\n' + "\n".join(cards) + '\n  </div>'


def section_html(title, count_label, body, note="", warning=""):
    note_html = f'<div class="section-note">{note}</div>' if note else ""
    warning_html = (
        f'<div class="section-note section-warning">\u26a0 {warning}</div>'
        if warning else ""
    )
    return f"""
  <div class="section">
    <div class="section-title">
      <h2>{title}</h2>
      <span class="count">{count_label}</span>
    </div>
    {note_html}
    {warning_html}
    {body}
  </div>
"""


def empty_state(message):
    return f'<div class="empty-state">{message}</div>'


def generated_line():
    return datetime.now().strftime("%d %B %Y \u00b7 %H:%M")


# ===========================================================================
# MODULE: Critical CVE Watch
# ===========================================================================

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")

NVD_API_KEY = get_key("NVD_API_KEY")
NVD_MIN_INTERVAL = 0.7 if NVD_API_KEY else 6.5   # public limit: 5 req / 30s
NVD_MAX_WINDOW_DAYS = 119                        # NVD hard cap: 120-day ranges
NVD_PAGE_SIZE = 2000

# Cap per (window, severity) fetch. v1 capped at 700 and *silently* dropped
# the overflow, which biased the yearly "top" rankings; v2 raises the cap
# and flags any truncation in the report so you know the pool was partial.
MAX_RECORDS_PER_WINDOW = 4000

CVSS_CUTOFF = 9.0       # base rule: "CVSS score greater than 9"
KEV_CVSS_CUTOFF = 7.0   # KEV-confirmed actively-exploited CVEs also qualify above this
FETCH_SEVERITIES = ("CRITICAL", "HIGH")  # HIGH fetched so sub-9 KEV entries are in the pool
TOP_N_30D = 10
TOP_N_365D = 10
MAX_SHOWN_7D = 25

_nvd_limiter = RateLimiter(NVD_MIN_INTERVAL)


def nvd_get(session, params, log):
    """Single rate-limited NVD request. Retries/backoff (incl. 429 with
    Retry-After) are handled by the session's HTTPAdapter."""
    _nvd_limiter.wait()
    try:
        resp = session.get(NVD_BASE, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        log(f"  ! NVD error: {e}")
        return None


def nvd_date(dt, end=False):
    # ISO-8601 with explicit UTC offset, as the NVD docs specify.
    suffix = "T23:59:59.999+00:00" if end else "T00:00:00.000+00:00"
    return dt.strftime("%Y-%m-%d") + suffix


def fetch_cve_window(session, start_dt, end_dt, log, severity=None,
                     max_records=MAX_RECORDS_PER_WINDOW):
    """Returns (cve_objects, truncated_flag)."""
    all_cves = []
    start_index = 0
    truncated = False

    while True:
        params = {
            "pubStartDate": nvd_date(start_dt),
            "pubEndDate": nvd_date(end_dt, end=True),
            "resultsPerPage": min(NVD_PAGE_SIZE, max_records - len(all_cves)),
            "startIndex": start_index,
        }
        if severity:
            params["cvssV3Severity"] = severity

        data = nvd_get(session, params, log)
        if not data:
            break

        vulns = data.get("vulnerabilities", [])
        all_cves.extend(v["cve"] for v in vulns if "cve" in v)

        total = data.get("totalResults", 0)
        start_index += len(vulns)

        if len(all_cves) >= max_records and start_index < total:
            truncated = True
            log(f"  ! Window {start_dt.date()}..{end_dt.date()} [{severity}] "
                f"holds {total} results; capped at {max_records}. "
                f"Rankings over this window are computed on a partial pool.")
            break
        if not vulns or start_index >= total:
            break

    return all_cves[:max_records], truncated


def fetch_cve_window_all_severities(session, start_dt, end_dt, log):
    """NVD can't OR severities in one call, so CRITICAL and HIGH are fetched
    separately and merged. HIGH matters because a KEV-listed 7.x CVE
    (CopyFail-style local chains) must be in the candidate pool at all."""
    merged, truncated = [], False
    for severity in FETCH_SEVERITIES:
        cves, trunc = fetch_cve_window(session, start_dt, end_dt, log, severity=severity)
        merged.extend(cves)
        truncated = truncated or trunc
    return merged, truncated


def build_windows(days_back, window_days=NVD_MAX_WINDOW_DAYS):
    windows = []
    end = datetime.now(timezone.utc)
    remaining = days_back
    while remaining > 0:
        span = min(window_days, remaining)
        start = end - timedelta(days=span)
        windows.append((start, end))
        end = start
        remaining -= span
    return windows


def fetch_kev_cve_ids(session, log):
    data = cached_json(session, KEV_URL, "kev_catalog.json",
                       max_age_hours=24, log=log, timeout=60)
    if not data:
        return set()
    return {v["cveID"] for v in data.get("vulnerabilities", [])}


def get_cvss(cve):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            return metrics[key][0].get("cvssData", {}).get("baseScore", 0) or 0
    return 0


def get_description(cve):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "").strip()
    return "No description available."


def get_product_label(cve):
    """Best-effort Vendor:Product from the first CPE criteria string."""
    for group in cve.get("configurations", []):
        for node in group.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) > 4:
                    vendor = parts[3].replace("_", " ").strip()
                    product = parts[4].replace("_", " ").strip()
                    vendor_l = vendor.title() if vendor not in ("*", "") else ""
                    product_l = product.title() if product not in ("*", "") else ""
                    if vendor_l and product_l:
                        return f"{vendor_l}:{product_l}"
                    if product_l:
                        return product_l
    return "Multiple / Unspecified"


def count_references(cve):
    """(total_refs, press/media-tagged refs). NVD tags references like
    'Press/Media Coverage' during enrichment - the closest real signal this
    API offers for media visibility. Caveat: enrichment lags publication by
    days-to-weeks, so for very recent CVEs these are usually zero."""
    total = media = 0
    for ref in cve.get("references", []):
        total += 1
        tags = [t.lower() for t in (ref.get("tags") or [])]
        if any("press" in t or "media" in t for t in tags):
            media += 1
    return total, media


def compute_impact_score(cvss_score, total_refs, media_refs, is_kev):
    """Heuristic 0-10 ranking aid (not an official score):
    55% CVSS + 25% media-tagged refs (cap 5) + 10% ref volume (cap 20)
    + 10% KEV bonus."""
    media_component = min(media_refs, 5) / 5 * 10
    ref_component = min(total_refs, 20) / 20 * 10
    kev_component = 10 if is_kev else 0
    score = (cvss_score * 0.55 + media_component * 0.25
             + ref_component * 0.10 + kev_component * 0.10)
    return round(min(score, 10.0), 1)


def build_cve_record(cve, kev_ids):
    cve_id = cve.get("id", "N/A")
    cvss_score = get_cvss(cve)
    is_kev = cve_id in kev_ids
    total_refs, media_refs = count_references(cve)
    return {
        "id": cve_id,
        "cvss": cvss_score,
        "product": get_product_label(cve),
        "description": get_description(cve),
        "published": (cve.get("published") or "")[:10],
        "is_kev": is_kev,
        "media_refs": media_refs,
        "total_refs": total_refs,
        "impact": compute_impact_score(cvss_score, total_refs, media_refs, is_kev),
    }


def dedupe_by_id(records):
    seen, unique = set(), []
    for r in records:
        if r["id"] not in seen:
            seen.add(r["id"])
            unique.append(r)
    return unique


def meets_criticality(r):
    """Qualifies if CVSS > 9.0, OR CISA-confirmed exploited (KEV) with
    CVSS > 7.0 - the KEV path catches high-impact local-access chains that
    CVSS alone under-scores."""
    return r["cvss"] > CVSS_CUTOFF or (r["is_kev"] and r["cvss"] > KEV_CVSS_CUTOFF)


# Fallback shown only when a live fetch fails entirely, clearly labeled in
# the HTML. Every entry satisfies meets_criticality (v1's list didn't).
FALLBACK_CVES = [
    {"id": "CVE-2024-4577", "cvss": 9.8, "product": "PHP",
     "description": "Argument-injection flaw in PHP-CGI on Windows allowing remote code execution via crafted HTTP requests; exploited in the wild within days of disclosure.",
     "published": "2024-06-09", "is_kev": True, "media_refs": 3, "total_refs": 10, "impact": 9.5},
    {"id": "CVE-2024-3400", "cvss": 10.0, "product": "Paloaltonetworks:Pan-Os",
     "description": "Command-injection vulnerability in Palo Alto Networks PAN-OS GlobalProtect enabling unauthenticated remote code execution; actively exploited (Operation MidnightEclipse).",
     "published": "2024-04-12", "is_kev": True, "media_refs": 4, "total_refs": 14, "impact": 9.9},
    {"id": "CVE-2024-38063", "cvss": 9.8, "product": "Microsoft:Windows",
     "description": "Remote code execution in the Windows TCP/IP stack via crafted IPv6 packets; wormable, no user interaction required.",
     "published": "2024-08-13", "is_kev": False, "media_refs": 2, "total_refs": 8, "impact": 9.3},
    {"id": "CVE-2024-23897", "cvss": 9.8, "product": "Jenkins",
     "description": "Arbitrary-file-read in the Jenkins CLI command parser leading to remote code execution; exploited against exposed Jenkins servers.",
     "published": "2024-01-24", "is_kev": True, "media_refs": 2, "total_refs": 9, "impact": 9.4},
    {"id": "CVE-2024-21413", "cvss": 9.8, "product": "Microsoft:Outlook",
     "description": "Remote code execution in Microsoft Outlook ('MonikerLink') bypassing Office Protected View.",
     "published": "2024-02-13", "is_kev": True, "media_refs": 1, "total_refs": 4, "impact": 8.8},
    {"id": "CVE-2024-26169", "cvss": 7.8, "product": "Microsoft:Windows",
     "description": "Windows Error Reporting Service elevation-of-privilege exploited as a zero-day by Black Basta operators before patch availability.",
     "published": "2024-03-12", "is_kev": True, "media_refs": 1, "total_refs": 5, "impact": 8.2},
]


def apply_fallback(records, label, log):
    if records:
        return records, False
    log(f"  ! No live results for '{label}', using fallback dataset.")
    return list(FALLBACK_CVES), True


def cve_card(record, rank):
    desc = truncate(record["description"], 320)
    kev_tag = (' <span style="color:var(--accent-2);">\U0001f3af Known Exploited (KEV)</span>'
               if record.get("is_kev") else "")
    return f"""
        <div class="actor-card">
            <div class="actor-rank">{rank_label(rank)}</div>
            <div class="actor-body">
                <div class="actor-top">
                    <div class="actor-name">{esc(record['id'])}{kev_tag}</div>
                    <div class="actor-count">{record['cvss']:.1f} <span>CVSS</span></div>
                </div>
                <div class="actor-desc">{esc(desc)}</div>
                <div class="actor-meta">
                    <span>\U0001f4e6 {esc(record['product'])}</span>
                    <span>\U0001f4ca Impact score: {record['impact']:.1f}</span>
                    <span>\U0001f4c5 {esc(record['published'] or 'Unknown')}</span>
                </div>
            </div>
        </div>
"""


CVE_CRITERIA_NOTE = (
    f"Qualifying criteria: CVSS &gt; {CVSS_CUTOFF:.0f}, OR CISA KEV-confirmed active "
    f"exploitation with CVSS &gt; {KEV_CVSS_CUTOFF:.0f} (catches high-impact local-access "
    "chains that CVSS alone scores below 9). Impact score is a separate heuristic combining "
    "CVSS, reference volume, press/media-tagged NVD references, and KEV status. NVD "
    "reference tagging lags publication, so for recent windows the media component is "
    "usually zero and the ranking leans on CVSS + KEV."
)

FALLBACK_WARNING = ("Live NVD data was unavailable for this section - showing static "
                    "fallback examples, not the current window.")
TRUNCATION_WARNING = ("One or more NVD query windows exceeded the fetch cap; this ranking "
                      "was computed over a partial pool (see console log).")


def cve_render(out_path, s7, s30, s365):
    (r7, fb7, tr7), (r30, fb30, tr30), (r365, fb365, tr365) = s7, s30, s365
    any_fallback = fb7 or fb30 or fb365

    def sec(title, count_label, data):
        records, fb, trunc = data
        body = "".join(cve_card(r, i) for i, r in enumerate(records)) \
               or empty_state("No CVEs matched this window.")
        warning = FALLBACK_WARNING if fb else (TRUNCATION_WARNING if trunc else "")
        return section_html(title, count_label, body, note=CVE_CRITERIA_NOTE, warning=warning)

    body = stat_grid([
        ("\U0001f525 Critical CVEs (7d)", len(r7)),
        ("\u26a0\ufe0f Critical CVEs (30d)", len(r30)),
        ("\U0001f30d Critical CVEs (365d)", len(r365)),
        ("\U0001f4c5 Report Date", datetime.now().strftime("%Y-%m-%d"), "font-size:22px;"),
    ])
    body += sec("\U0001f6a8 Most Critical CVEs (Last 7 Days)",
                f"{len(r7)} CVEs \u00b7 newest first", s7)
    body += sec("\U0001f3c6 Most Critical CVEs (Last 30 Days)",
                f"Top {TOP_N_30D} by impact \u00b7 shown newest first", s30)
    body += sec("\U0001f4f0 Most Critical CVEs (Last 365 Days)",
                f"Top {TOP_N_365D} by impact \u00b7 shown newest first", s365)

    html = render_page(
        "cve", "CVE Threat Report", "Vulnerability Intelligence Digest",
        "\U0001f6e1\ufe0f Critical CVE Watch",
        f"Generated {generated_line()} \u00b7 data via NVD API"
        + (" &amp; Fallback" if any_fallback else ""),
        body,
        "Generated by CVE Watch \u00b7 Data sourced from NVD API"
        + (" with fallback data" if any_fallback else ""),
    )
    out_path.write_text(html, encoding="utf-8")
    return out_path


def cve_main(log):
    now = datetime.now(timezone.utc)
    session = make_session(pool_size=4,
                           extra_headers={"apiKey": NVD_API_KEY} if NVD_API_KEY else None)
    if not NVD_API_KEY:
        log("  (No NVD_API_KEY found - running at the public rate limit; "
            "the 365-day section will be slow. Get a free key at "
            "nvd.nist.gov/developers/request-an-api-key)")

    log("Fetching CISA KEV catalog...")
    kev_ids = fetch_kev_cve_ids(session, log)

    def collect(days, label):
        raw, truncated = [], False
        for start, end in build_windows(days):
            if days > NVD_MAX_WINDOW_DAYS:
                log(f"  Window {start.date()} to {end.date()}...")
            cves, trunc = fetch_cve_window_all_severities(session, start, end, log)
            raw.extend(cves)
            truncated = truncated or trunc
        records = [build_cve_record(c, kev_ids) for c in raw]
        records = [r for r in dedupe_by_id(records) if meets_criticality(r)]
        log(f"  {label}: {len(records)} qualifying CVEs.")
        return records, truncated

    log("Fetching CVEs from the last 7 days...")
    r7, tr7 = collect(7, "last 7 days")
    r7.sort(key=lambda r: r["cvss"], reverse=True)
    r7 = r7[:MAX_SHOWN_7D]
    r7.sort(key=lambda r: r["published"] or "0000-00-00", reverse=True)
    r7, fb7 = apply_fallback(r7, "last 7 days", log)

    log("Fetching CVEs from the last 30 days...")
    r30, tr30 = collect(30, "last 30 days")
    r30.sort(key=lambda r: r["impact"], reverse=True)
    r30 = r30[:TOP_N_30D]
    r30.sort(key=lambda r: r["published"] or "0000-00-00", reverse=True)
    r30, fb30 = apply_fallback(r30, "last 30 days", log)

    log("Fetching CVEs from the last 365 days...")
    r365, tr365 = collect(365, "last 365 days")
    r365.sort(key=lambda r: r["impact"], reverse=True)
    r365 = r365[:TOP_N_365D]
    r365.sort(key=lambda r: r["published"] or "0000-00-00", reverse=True)
    r365, fb365 = apply_fallback(r365, "last 365 days", log)

    log("Generating report...")
    return cve_render(RUN_DIR / "cve.html",
                      (r7, fb7, tr7), (r30, fb30, tr30), (r365, fb365, tr365))


# ===========================================================================
# MODULE: Ransomware Watch
# ===========================================================================

RANSOMWATCH_BASE = "https://api.ransomware.live/v2"
RANSOMWARE_API_KEY = get_key("RANSOMWARE_LIVE_API_KEY")

MONTHS_TO_ANALYZE = 3    # trend window for top actors/sectors/countries
YEARLY_MONTHS = 13       # 13 so a partial current month still covers a full year
TOP_N_ACTORS = 10
TOP_N_SECTORS = 10
TOP_N_COUNTRIES = 10
TOP_N_YEARLY_ATTACKS = 10
RECENT_VICTIMS_SHOWN = 15

RSW_DATE_KEYS = ("discovered", "published", "attackdate", "date", "added")


def rsw_get(session, path, log, params=None, timeout=25):
    url = f"{RANSOMWATCH_BASE}{path}"
    try:
        resp = session.get(url, params=params, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        log(f"  ! Error fetching {url}: {e}")
        return None


def parse_victim_date(v):
    for key in RSW_DATE_KEYS:
        raw = v.get(key)
        if not raw:
            continue
        raw = str(raw).strip()
        if not raw or raw.lower() in ("unknown", "n/a", "none"):
            continue
        candidates = (raw, raw.replace("Z", "+00:00"))
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            for c in candidates:
                try:
                    dt = datetime.strptime(c, fmt)
                    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
        match = re.search(r"\d{4}-\d{2}-\d{2}", raw)
        if match:
            try:
                return datetime.strptime(match.group(), "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                pass
    return None


def clean_label(value, default="Unknown"):
    if not value or str(value).strip().lower() in ("", "none", "n/a", "unknown"):
        return default
    return str(value).strip()


def dedupe_victims(victims):
    seen, unique = set(), []
    for v in victims:
        key = (clean_label(v.get("victim")).lower(),
               clean_label(v.get("group")).lower(),
               clean_label(v.get("attackdate", v.get("discovered", ""))))
        if key not in seen:
            seen.add(key)
            unique.append(v)
    return unique


def compute_rsw_impact(v):
    """Heuristic: ransomware.live exposes no severity/loss score, so this
    ranks by public signal - infostealer record counts (Hudson Rock
    enrichment, weighted heaviest), press coverage, and posted updates."""
    infostealer_total = 0
    infostealer = v.get("infostealer")
    if isinstance(infostealer, dict):
        for val in infostealer.values():
            if isinstance(val, (int, float)):
                infostealer_total += val
            elif isinstance(val, str) and val.strip().isdigit():
                infostealer_total += int(val.strip())
    press_count = len(v.get("press") or [])
    updates_count = len(v.get("updates") or [])
    return {
        "score": infostealer_total * 10 + press_count * 5 + updates_count * 2,
        "infostealer_total": infostealer_total,
        "press_count": press_count,
        "updates_count": updates_count,
    }


def rsw_fetch_all(session, log):
    """recentvictims + 13 monthly pages + group profiles, with the monthly
    pages fetched in parallel (they were the bulk of v1's wall time)."""
    today = datetime.now(timezone.utc)
    months = []
    y, m = today.year, today.month
    for i in range(YEARLY_MONTHS):
        mm, yy = m - i, y
        while mm <= 0:
            mm += 12
            yy -= 1
        months.append((yy, mm))

    monthly = {}
    recent, groups_raw = [], None

    def fetch_month(ym):
        yy, mm = ym
        data = rsw_get(session, f"/victims/{yy}/{mm:02d}", log)
        return ym, data if isinstance(data, list) else []

    log(f"Fetching recent victims, group profiles, and {YEARLY_MONTHS} months "
        f"of history in parallel...")
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(fetch_month, ym): ("month", ym) for ym in months}
        futures[pool.submit(rsw_get, session, "/recentvictims", log)] = ("recent", None)
        futures[pool.submit(cached_json, session, f"{RANSOMWATCH_BASE}/groups",
                            "ransomware_groups.json", 24, log)] = ("groups", None)
        for future in as_completed(futures):
            kind, _ = futures[future]
            result = future.result()
            if kind == "month":
                ym, victims = result
                monthly[ym] = victims
            elif kind == "recent":
                recent = result if isinstance(result, list) else []
            else:
                groups_raw = result

    ordered_months = [monthly.get(ym, []) for ym in months]  # most recent first
    groups_by_name = {}
    if isinstance(groups_raw, list):
        groups_by_name = {g.get("name", "").strip().lower(): g
                          for g in groups_raw if isinstance(g, dict)}
    return recent, ordered_months, groups_by_name


def rsw_analyze(recent_victims, period_victims, yearly_victims, groups_by_name):
    period_victims = dedupe_victims(period_victims)
    yearly_victims = dedupe_victims(yearly_victims)

    def top_counts(field, n):
        # "Unknown" is excluded from the top lists - it wins the count
        # without telling the reader anything.
        counter = Counter(clean_label(v.get(field)) for v in period_victims)
        counter.pop("Unknown", None)
        return counter.most_common(n)

    top_actors = top_counts("group", TOP_N_ACTORS)
    top_sectors = top_counts("sector", TOP_N_SECTORS)
    top_countries = top_counts("country", TOP_N_COUNTRIES)

    now = datetime.now(timezone.utc)
    cutoff_24h = now - timedelta(hours=24)
    cutoff_365d = now - timedelta(days=365)

    victims_24h = [v for v in recent_victims
                   if (dt := parse_victim_date(v)) and dt >= cutoff_24h]

    yearly_in_window = [v for v in yearly_victims
                        if (dt := parse_victim_date(v)) is None or dt >= cutoff_365d]

    scored = [(v, imp) for v in yearly_in_window
              if (imp := compute_rsw_impact(v))["score"] > 0]
    scored.sort(key=lambda pair: pair[1]["score"], reverse=True)

    enriched_actors = []
    for name, count in top_actors:
        profile = groups_by_name.get(name.lower(), {})
        enriched_actors.append({
            "name": name,
            "count": count,
            "description": profile.get("description") or "",
            "locations": len(profile.get("locations") or []),
        })

    return {
        "top_actors": enriched_actors,
        "top_sectors": top_sectors,
        "top_countries": top_countries,
        "victims_24h": victims_24h,
        "period_total": len(period_victims),
        "yearly_total": len(yearly_in_window),
        "top_attacks": scored[:TOP_N_YEARLY_ATTACKS],
        "unique_groups": len({clean_label(v.get("group")) for v in period_victims}),
        "unique_countries": len({clean_label(v.get("country")) for v in period_victims}),
    }


def bar_rows(pairs, color):
    max_count = max((c for _, c in pairs), default=1)
    rows = ""
    for label, count in pairs:
        pct = max(6, int((count / max_count) * 100)) if max_count else 6
        rows += f"""
        <div class="bar-row">
          <div class="bar-label">{esc(label)}</div>
          <div class="bar-track">
            <div class="bar-fill" style="width:{pct}%;background:{color};"></div>
          </div>
          <div class="bar-count">{count}</div>
        </div>
"""
    return rows


def rsw_actor_cards(actors):
    cards = ""
    for i, actor in enumerate(actors):
        desc = truncate(actor["description"].strip(), 220)
        desc_html = f'<div class="actor-desc">{esc(desc)}</div>' if desc else ""
        loc_html = (f'<span>\U0001f310 {actor["locations"]} leak sites</span>'
                    if actor["locations"] else "")
        cards += f"""
        <div class="actor-card">
          <div class="actor-rank">{rank_label(i)}</div>
          <div class="actor-body">
            <div class="actor-top">
              <div class="actor-name caps">{esc(actor['name'])}</div>
              <div class="actor-count">{actor['count']} <span>victims</span></div>
            </div>
            {desc_html}
            <div class="actor-meta">{loc_html}</div>
          </div>
        </div>
"""
    return cards


def victim_fields(v):
    return (clean_label(v.get("victim"), "Redacted / Unknown"),
            clean_label(v.get("group")),
            clean_label(v.get("country"), "\u2014"),
            clean_label(v.get("sector"), "\u2014"),
            clean_label(v.get("attackdate") or v.get("discovered")
                        or v.get("published"), "\u2014"))


def rsw_attack_cards(scored_attacks):
    cards = ""
    for i, (v, impact) in enumerate(scored_attacks):
        name, group, country, sector, date_display = victim_fields(v)
        signals = []
        if impact["infostealer_total"]:
            signals.append(f'\U0001f5c2 {impact["infostealer_total"]:,} exposed records')
        if impact["press_count"]:
            signals.append(f'\U0001f4f0 {impact["press_count"]} press mentions')
        if impact["updates_count"]:
            signals.append(f'\U0001f504 {impact["updates_count"]} updates')
        signals_html = "".join(f"<span>{s}</span>" for s in signals)
        cards += f"""
        <div class="actor-card">
          <div class="actor-rank">{rank_label(i)}</div>
          <div class="actor-body">
            <div class="actor-top">
              <div class="actor-name caps">{esc(name)}</div>
              <div class="actor-count">{esc(group)}</div>
            </div>
            <div class="actor-meta" style="margin-top:6px;">
              <span>\U0001f3ed {esc(sector)}</span>
              <span>\U0001f30d {esc(country)}</span>
              <span>\U0001f4c5 {esc(date_display)}</span>
            </div>
            <div class="actor-meta warm" style="margin-top:6px;">{signals_html}</div>
          </div>
        </div>
"""
    return cards


def rsw_victim_rows(victims):
    rows = ""
    for v in victims:
        name, group, country, sector, date_display = victim_fields(v)
        rows += f"""
        <div class="victim-row">
          <div class="victim-main">
            <span class="victim-name">{esc(name)}</span>
            <span class="victim-group">{esc(group)}</span>
          </div>
          <div class="victim-meta">
            <span>\U0001f3ed {esc(sector)}</span>
            <span>\U0001f30d {esc(country)}</span>
            <span>\U0001f4c5 {esc(date_display)}</span>
          </div>
        </div>
"""
    return rows


def rsw_render(out_path, analysis, recent_victims):
    body = stat_grid([
        ("\U0001f6a8 New in Last 24h", len(analysis["victims_24h"])),
        ("\U0001f9ec Active Threat Actors", analysis["unique_groups"]),
        (f"\U0001f3e2 Victims ({MONTHS_TO_ANALYZE} months)", analysis["period_total"]),
        ("\U0001f30d Countries Hit", analysis["unique_countries"]),
    ])

    body += section_html(
        "Top Threat Actors", f"by victim count, last {MONTHS_TO_ANALYZE} months",
        rsw_actor_cards(analysis["top_actors"]) or empty_state("No actor data available."))

    body += section_html(
        "\U0001f4a5 Top 10 High-Impact Attacks",
        f"last 365 days \u00b7 {analysis['yearly_total']} tracked",
        rsw_attack_cards(analysis["top_attacks"])
        or empty_state("No attacks with enough signal to rank were found in this window."),
        note=('"Impact" here is a heuristic, not a verified damage figure \u2014 it weighs '
              'exposed infostealer record counts, press coverage volume, and posted incident '
              "updates, since ransomware.live doesn't publish a severity/loss score directly."))

    body += section_html(
        "\U0001f4ca Top Sectors Affected", "by victim count",
        bar_rows(analysis["top_sectors"], "#f43f5e")
        or empty_state("No sector data available."))

    body += section_html(
        "\U0001f30d Top Countries Affected", "by victim count",
        bar_rows(analysis["top_countries"], "#fb923c")
        or empty_state("No country data available."))

    body += section_html(
        "\U0001f552 Most Recent Victims",
        f"{min(len(recent_victims), RECENT_VICTIMS_SHOWN)} shown",
        rsw_victim_rows(recent_victims[:RECENT_VICTIMS_SHOWN])
        or empty_state("No recent victim data available."))

    html = render_page(
        "rsw", "Ransomware Threat Report", "Threat Intelligence Digest",
        "\U0001f3f4\u200d\u2620\ufe0f Ransomware Watch",
        f"Generated {generated_line()} \u00b7 data via ransomware.live",
        body,
        "Generated by Ransomware Watch \u00b7 Data sourced from ransomware.live "
        "(Julien Mousqueton)")
    out_path.write_text(html, encoding="utf-8")
    return out_path


def rsw_main(log):
    headers = {"X-API-KEY": RANSOMWARE_API_KEY} if RANSOMWARE_API_KEY else None
    session = make_session(pool_size=8, extra_headers=headers)

    recent, ordered_months, groups_by_name = rsw_fetch_all(session, log)

    period_victims = [v for month in ordered_months[:MONTHS_TO_ANALYZE] for v in month]
    yearly_victims = [v for month in ordered_months for v in month]

    log("Analyzing...")
    analysis = rsw_analyze(recent, period_victims, yearly_victims, groups_by_name)

    log("Generating report...")
    return rsw_render(RUN_DIR / "ransomware.html", analysis, recent)


# ===========================================================================
# MODULE: Cyber News Wire
# ===========================================================================

RSS_FEEDS = {
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
    "SecurityWeek": "https://www.securityweek.com/feed/",
    "The Record": "https://therecord.media/feed/",
    "Infosecurity Magazine": "https://www.infosecurity-magazine.com/rss/news/",
    "Graham Cluley": "https://grahamcluley.com/feed/",
}

PER_FEED_LIMIT = 60
TOP_N_IMPORTANT = 10
MIN_SOURCES_FOR_IMPORTANT = 2
NEWS_DESC_MAX_CHARS = 240

# A signal shared by more than this many articles is too generic to identify
# "the same story" and is ignored for clustering.
MAX_ARTICLES_PER_SIGNAL = 15

PALETTE = ["#14b8a6", "#6366f1", "#f43f5e", "#fb923c", "#eab308",
           "#22d3ee", "#a78bfa", "#4ade80", "#f472b6", "#38bdf8"]
SOURCE_COLORS = {name: PALETTE[i % len(PALETTE)] for i, name in enumerate(RSS_FEEDS)}

SIGNAL_STOPWORDS = {
    "the", "this", "that", "these", "those", "new", "how", "why", "what",
    "after", "amid", "over", "its", "his", "her", "they", "are", "was",
    "with", "from", "for", "and", "but", "not", "you", "your", "top",
    "best", "week", "days", "report", "news", "says", "said", "will",
    "can", "now", "just", "more", "most", "first", "second", "third",
    "hackers", "hacker", "attack", "attacks", "security", "cyber",
    "cybersecurity", "breach", "data", "vulnerability", "vulnerabilities",
    "exploit", "exploited", "malware", "ransomware", "flaw", "flaws",
    "warns", "warning", "critical", "targets", "targeted", "using",
    "million", "billion", "researchers", "update", "patch", "patches",
}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def parse_entry_date(entry):
    struct = entry.get("published_parsed") or entry.get("updated_parsed")
    if not struct:
        return None
    try:
        # feedparser normalizes to UTC struct_time; timegm (not mktime) is
        # the correct inverse, since mktime would assume local time.
        return datetime.fromtimestamp(calendar.timegm(struct), tz=timezone.utc)
    except (ValueError, OverflowError):
        return None


def build_article(source, entry):
    dt = parse_entry_date(entry)
    if dt is None:
        return None
    title = strip_tags(entry.get("title", "Untitled"))
    description = truncate(
        strip_tags(entry.get("summary", "") or entry.get("description", "")),
        NEWS_DESC_MAX_CHARS)
    return {
        "source": source,
        "title": title,
        "description": description or "No description available.",
        "link": entry.get("link", ""),
        "datetime": dt,
    }


def fetch_all_articles(session, log):
    """All feeds fetched in parallel - one slow feed no longer blocks the
    module (v1 fetched them sequentially)."""
    def fetch_one(item):
        name, url = item
        try:
            resp = session.get(url, timeout=15)
            resp.raise_for_status()
            return name, feedparser.parse(resp.content).entries[:PER_FEED_LIMIT]
        except Exception as e:
            log(f"  ! Error fetching {name}: {e}")
            return name, []

    articles = []
    with ThreadPoolExecutor(max_workers=len(RSS_FEEDS)) as pool:
        for name, entries in pool.map(fetch_one, RSS_FEEDS.items()):
            count = 0
            for entry in entries:
                article = build_article(name, entry)
                if article:
                    articles.append(article)
                    count += 1
            log(f"  {name}: {count} dated articles.")
    return articles


def extract_signals(title):
    signals = {m.upper() for m in CVE_RE.findall(title)}
    for word in re.findall(r"[A-Z][a-zA-Z0-9&]{2,}", title):
        wl = word.lower()
        if wl not in SIGNAL_STOPWORDS:
            signals.add(wl)
    return signals


class DisjointSet:
    def __init__(self, n):
        self.parent = list(range(n))

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


def cluster_important_stories(weekly_articles):
    """Groups the week's articles into stories.

    v1 merged any two articles sharing a single capitalized word, so one
    common vendor name could chain-merge unrelated stories into a
    mega-cluster titled by whichever article happened to be oldest. v2
    only merges when two articles share a CVE ID, or share >=2 distinct
    name signals - and ignores signals so common they identify nothing.
    """
    if not weekly_articles:
        return []

    signal_to_indices = defaultdict(list)
    for i, a in enumerate(weekly_articles):
        for s in extract_signals(a["title"]):
            signal_to_indices[s].append(i)

    pair_counts = Counter()
    strong_pairs = set()
    for sig, indices in signal_to_indices.items():
        if len(indices) < 2 or len(indices) > MAX_ARTICLES_PER_SIGNAL:
            continue
        is_cve = sig.startswith("CVE-")
        for i in range(len(indices)):
            for j in range(i + 1, len(indices)):
                pair = (indices[i], indices[j])
                if is_cve:
                    strong_pairs.add(pair)
                else:
                    pair_counts[pair] += 1

    dsu = DisjointSet(len(weekly_articles))
    for pair, count in pair_counts.items():
        if count >= 2:
            dsu.union(*pair)
    for pair in strong_pairs:
        dsu.union(*pair)

    groups = defaultdict(list)
    for i in range(len(weekly_articles)):
        groups[dsu.find(i)].append(i)

    clusters = []
    for indices in groups.values():
        group_articles = sorted((weekly_articles[i] for i in indices),
                                key=lambda a: a["datetime"])
        distinct_sources = {a["source"] for a in group_articles}
        if len(distinct_sources) < MIN_SOURCES_FOR_IMPORTANT:
            continue
        first = group_articles[0]
        clusters.append({
            "title": first["title"],
            "description": first["description"],
            "first_reported_by": first["source"],
            "first_reported_at": first["datetime"],
            "sources": sorted(({"name": a["source"], "link": a["link"]}
                               for a in group_articles), key=lambda s: s["name"]),
            "distinct_source_count": len(distinct_sources),
            "weight": len(distinct_sources) * 10 + len(group_articles) * 2,
        })

    clusters.sort(key=lambda c: c["weight"], reverse=True)
    return clusters[:TOP_N_IMPORTANT]


def dedupe_sources(sources):
    seen, unique = set(), []
    for s in sources:
        if s["name"] not in seen:
            seen.add(s["name"])
            unique.append(s)
    return unique


def time_ago(dt):
    seconds = (datetime.now(timezone.utc) - dt).total_seconds()
    if seconds < 3600:
        return f"{max(1, int(seconds // 60))}m ago"
    if seconds < 86400:
        return f"{int(seconds // 3600)}h ago"
    return f"{int(seconds // 86400)}d ago"


def source_badge(name):
    color = SOURCE_COLORS.get(name, "#64748b")
    return (f'<span class="badge" style="background:{color}22;color:{color};'
            f'border:1px solid {color}55;">{esc(name)}</span>')


def news_card(a):
    return f"""
        <div class="news-item">
          <div class="news-top">
            <a class="news-title" href="{esc(a['link'])}" target="_blank" rel="noopener">{esc(a['title'])}</a>
            {source_badge(a['source'])}
          </div>
          <div class="news-desc">{esc(a['description'])}</div>
          <div class="news-meta">
            <span>\U0001f552 {a['datetime'].strftime('%d %b, %H:%M UTC')} \u00b7 {time_ago(a['datetime'])}</span>
            <a href="{esc(a['link'])}" target="_blank" rel="noopener">\U0001f517 Read source</a>
          </div>
        </div>
"""


def important_card(cluster, rank):
    sources_html = "".join(
        f'<a class="source-chip" href="{esc(s["link"])}" target="_blank" '
        f'rel="noopener">{source_badge(s["name"])}</a>'
        for s in dedupe_sources(cluster["sources"]))
    return f"""
        <div class="actor-card alt">
          <div class="actor-rank">{rank_label(rank)}</div>
          <div class="actor-body">
            <div class="actor-top">
              <div class="actor-name plain">{esc(cluster['title'])}</div>
              <div class="actor-count">{cluster['distinct_source_count']} <span>sources</span></div>
            </div>
            <div class="actor-desc">{esc(cluster['description'])}</div>
            <div class="actor-meta" style="margin-bottom:10px;">
              <span>\U0001f4f0 First reported by {esc(cluster['first_reported_by'])}</span>
              <span>\U0001f552 {cluster['first_reported_at'].strftime('%d %b, %H:%M UTC')}</span>
              <span>\U0001f4c8 Weight: {cluster['weight']}</span>
            </div>
            <div class="source-chips">{sources_html}</div>
          </div>
        </div>
"""


def news_render(out_path, last24, clusters):
    body = stat_grid([
        ("\U0001f195 Articles (24h)", len(last24)),
        ("\U0001f4e1 Sources Monitored", len(RSS_FEEDS)),
        ("\U0001f525 Important Stories (7d)", len(clusters)),
        ("\U0001f4c5 Report Time", datetime.now().strftime("%H:%M"), "font-size:20px;"),
    ])

    body += section_html(
        "\U0001f552 Cybersecurity News \u2014 Last 24 Hours", f"{len(last24)} articles",
        "".join(news_card(a) for a in last24)
        or empty_state("No articles published in the last 24 hours across monitored sources."))

    body += section_html(
        "\U0001f525 Important News This Week", f"top {TOP_N_IMPORTANT} by cross-source coverage",
        "".join(important_card(c, i) for i, c in enumerate(clusters))
        or empty_state("No story was covered by enough independent sources this week to qualify."),
        note=('"Important" here means multiple outlets independently covered the same story '
              "\u2014 articles are grouped when they share a CVE ID or at least two distinctive "
              "named entities in their titles, then ranked by how many distinct sources picked "
              "the story up. This is a coverage-volume heuristic, not an official severity "
              "rating."))

    html = render_page(
        "news", "Cybersecurity News Digest", "Cybersecurity News Digest",
        "\U0001f4e1 Cyber News Wire",
        f"Generated {generated_line()}",
        body,
        f"Generated by Cyber News Wire \u00b7 Aggregated from {len(RSS_FEEDS)} "
        "security news RSS feeds")
    out_path.write_text(html, encoding="utf-8")
    return out_path


def news_main(log):
    now = datetime.now(timezone.utc)
    session = make_session(pool_size=len(RSS_FEEDS))

    log("Fetching articles from all sources (parallel)...")
    all_articles = fetch_all_articles(session, log)
    log(f"  Retrieved {len(all_articles)} dated articles total.")

    weekly = [a for a in all_articles if a["datetime"] >= now - timedelta(days=7)]
    last24 = sorted((a for a in weekly if a["datetime"] >= now - timedelta(hours=24)),
                    key=lambda a: a["datetime"], reverse=True)

    log("Clustering the week's coverage for cross-source importance...")
    clusters = cluster_important_stories(weekly)

    log("Generating report...")
    return news_render(RUN_DIR / "news.html", last24, clusters)


# ===========================================================================
# MODULE: Threat Actor & Breach Watch
# ===========================================================================

ATTACK_STIX_URL = ("https://raw.githubusercontent.com/mitre/cti/master/"
                   "enterprise-attack/enterprise-attack.json")
HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"

TOP_N_GROUPS = 12
MAX_TECHNIQUES_PER_GROUP = 8
MAX_CAMPAIGNS_PER_GROUP = 4
MAX_SOFTWARE_PER_GROUP = 6
MIN_TECHNIQUES_TO_QUALIFY = 3
TOP_N_YEARLY_BREACHES = 10
TTP_DESC_MAX_CHARS = 380

CITATION_RE = re.compile(r"\(Citation:[^)]*\)")
MD_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]+\)")


def clean_stix_text(text):
    """Strip STIX '(Citation: ...)' markers and flatten markdown links."""
    text = CITATION_RE.sub("", text or "")
    text = MD_LINK_RE.sub(r"\1", text)
    return re.sub(r"\s+", " ", text).strip()


def get_attack_ref(obj, field):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get(field, "")
    return ""


def get_tactic(technique_obj):
    for phase in technique_obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack":
            return phase.get("phase_name", "").replace("-", " ").title()
    return "Unspecified"


def extract_informal_campaigns(description):
    """Fallback for groups with no formally modeled Campaign object: mine
    'Operation X' style names from the group description. Labeled as
    informal in the UI."""
    matches = re.findall(r"Operation [A-Z][\w]*(?:\s[A-Z][\w]*){0,3}", description)
    return sorted(set(matches))[:MAX_CAMPAIGNS_PER_GROUP]


def is_live(obj):
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def build_apt_records(bundle):
    objects = bundle.get("objects", [])

    groups = [o for o in objects if o.get("type") == "intrusion-set" and is_live(o)]
    campaigns_by_id = {o["id"]: o for o in objects
                       if o.get("type") == "campaign" and is_live(o)}
    techniques_by_id = {o["id"]: o for o in objects
                        if o.get("type") == "attack-pattern" and is_live(o)}
    software_by_id = {o["id"]: o for o in objects
                      if o.get("type") in ("malware", "tool") and is_live(o)}

    group_technique_ids = defaultdict(set)
    group_software_ids = defaultdict(set)
    group_campaign_ids = defaultdict(set)

    for rel in objects:
        if rel.get("type") != "relationship":
            continue
        rtype = rel.get("relationship_type")
        src, tgt = rel.get("source_ref", ""), rel.get("target_ref", "")
        if rtype == "uses" and src.startswith("intrusion-set--"):
            if tgt.startswith("attack-pattern--"):
                group_technique_ids[src].add(tgt)
            elif tgt.startswith(("malware--", "tool--")):
                group_software_ids[src].add(tgt)
        elif (rtype == "attributed-to" and src.startswith("campaign--")
              and tgt.startswith("intrusion-set--")):
            group_campaign_ids[tgt].add(src)

    # Rank by ATT&CK entry recency (best available proxy for "actively
    # tracked"; see the section note), technique breadth as tiebreaker.
    groups.sort(key=lambda g: (g.get("modified", "1970-01-01"),
                               len(group_technique_ids.get(g["id"], ()))),
                reverse=True)

    records = []
    for g in groups:
        tech_ids = group_technique_ids.get(g["id"], set())
        if len(tech_ids) < MIN_TECHNIQUES_TO_QUALIFY:
            continue

        name = g.get("name", "Unknown")
        description = clean_stix_text(g.get("description", ""))

        techniques = sorted(
            ({"attack_id": get_attack_ref(t, "external_id"),
              "name": t.get("name", "Unknown Technique"),
              "tactic": get_tactic(t)}
             for tid in tech_ids if (t := techniques_by_id.get(tid))),
            key=lambda t: t["attack_id"])

        software = sorted(s.get("name", "Unknown")
                          for sid in group_software_ids.get(g["id"], set())
                          if (s := software_by_id.get(sid)))

        campaigns = []
        for cid in group_campaign_ids.get(g["id"], set()):
            c = campaigns_by_id.get(cid)
            if not c:
                continue
            campaigns.append({
                "attack_id": get_attack_ref(c, "external_id"),
                "name": c.get("name", "Unnamed Campaign"),
                "description": truncate(clean_stix_text(c.get("description", "")), 220),
                "first_seen": (c.get("first_seen") or "")[:10] or "Unknown",
                "last_seen": (c.get("last_seen") or "")[:10] or "Unknown",
                "formal": True,
            })

        used_informal = False
        if not campaigns:
            campaigns = [{"attack_id": "", "name": n, "description": "",
                          "first_seen": "Unknown", "last_seen": "Unknown",
                          "formal": False}
                         for n in extract_informal_campaigns(description)]
            used_informal = bool(campaigns)

        records.append({
            "attack_id": get_attack_ref(g, "external_id"),
            "url": get_attack_ref(g, "url"),
            "name": name,
            "aliases": [a for a in g.get("aliases", []) if a != name],
            "description": truncate(description, TTP_DESC_MAX_CHARS),
            "last_updated": (g.get("modified") or "")[:10] or "Unknown",
            "techniques": techniques[:MAX_TECHNIQUES_PER_GROUP],
            "technique_total": len(techniques),
            "campaigns": campaigns[:MAX_CAMPAIGNS_PER_GROUP],
            "campaigns_informal": used_informal,
            "software": software[:MAX_SOFTWARE_PER_GROUP],
            "software_total": len(software),
        })
        if len(records) >= TOP_N_GROUPS:
            break

    return records


def parse_hibp_date(raw):
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            return datetime.strptime(raw[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            return None


def build_breach_record(b):
    # HIBP descriptions are raw HTML (they embed <a> tags) - strip tags
    # here; esc() at render handles the rest.
    return {
        "name": b.get("Title") or b.get("Name") or "Unknown",
        "domain": b.get("Domain") or "\u2014",
        "breach_date": b.get("BreachDate", "Unknown"),
        "added_date": parse_hibp_date(b.get("AddedDate")),
        "pwn_count": b.get("PwnCount", 0) or 0,
        "description": truncate(strip_tags(b.get("Description", "")), 260),
        "data_classes": b.get("DataClasses") or [],
        "is_verified": b.get("IsVerified", False),
        "is_sensitive": b.get("IsSensitive", False),
    }


def technique_chip(t):
    label = f"{t['attack_id']}: {t['name']}" if t["attack_id"] else t["name"]
    return f'<span class="chip" title="{esc(t["tactic"])}">{esc(label)}</span>'


def campaign_block(c):
    if c["formal"]:
        header = f"{c['attack_id']}: {c['name']}" if c["attack_id"] else c["name"]
        desc = (f'<div class="campaign-desc">{esc(c["description"])}</div>'
                if c["description"] else "")
        return f"""
            <div class="campaign-item">
              <div class="campaign-name">{esc(header)}</div>
              <div class="campaign-dates">\U0001f4c5 {esc(c['first_seen'])} \u2192 {esc(c['last_seen'])}</div>
              {desc}
            </div>
"""
    return f"""
            <div class="campaign-item campaign-informal">
              <div class="campaign-name">{esc(c['name'])}</div>
              <div class="campaign-dates">\u26a0\ufe0f mentioned in group description, not a formally modeled ATT&amp;CK campaign</div>
            </div>
"""


def apt_card(r):
    aliases_html = (f'<div class="aka">aka {esc(", ".join(r["aliases"]))}</div>'
                    if r["aliases"] else "")

    techniques_html = "".join(technique_chip(t) for t in r["techniques"])
    more_tech = r["technique_total"] - len(r["techniques"])
    if more_tech > 0:
        techniques_html += f'<span class="chip chip-muted">+{more_tech} more</span>'

    software_html = "".join(f'<span class="chip chip-alt">{esc(s)}</span>'
                            for s in r["software"])
    more_sw = r["software_total"] - len(r["software"])
    if more_sw > 0:
        software_html += f'<span class="chip chip-alt chip-muted">+{more_sw} more</span>'

    campaigns_html = "".join(campaign_block(c) for c in r["campaigns"]) or (
        '<div class="campaign-item campaign-informal"><div class="campaign-dates">'
        'No named campaigns documented for this group in ATT&amp;CK.</div></div>')

    id_label = f"{r['attack_id']} \u00b7 {r['name']}" if r["attack_id"] else r["name"]

    software_section = (f'''<div class="apt-subsection">
            <div class="apt-subtitle">\U0001f9f0 Software / Tools ({r["software_total"]} total)</div>
            <div class="chip-list">{software_html}</div>
          </div>''' if software_html else "")

    return f"""
        <div class="apt-card">
          <div class="apt-top">
            <div>
              <div class="apt-name"><a href="{esc(r['url'])}" target="_blank" rel="noopener">{esc(id_label)}</a></div>
              {aliases_html}
            </div>
            <span class="badge">\U0001f552 ATT&amp;CK updated {esc(r['last_updated'])}</span>
          </div>
          <div class="apt-desc">{esc(r['description'])}</div>

          <div class="apt-subsection">
            <div class="apt-subtitle">\U0001f3af Campaigns</div>
            <div class="campaign-list">{campaigns_html}</div>
          </div>

          <div class="apt-subsection">
            <div class="apt-subtitle">\U0001f5e1\ufe0f TTPs Used ({r['technique_total']} total)</div>
            <div class="chip-list">{techniques_html}</div>
          </div>

          {software_section}
        </div>
"""


def breach_card(b, show_rank=None):
    rank_html = (f'<div class="actor-rank">{rank_label(show_rank)}</div>'
                 if show_rank is not None else "")
    verified = ('<span class="badge badge-verified">\u2713 Verified</span>'
                if b["is_verified"]
                else '<span class="badge badge-unverified">Unverified</span>')
    sensitive = ('<span class="badge badge-sensitive">\u26a0\ufe0f Sensitive</span>'
                 if b["is_sensitive"] else "")
    classes_html = "".join(f'<span class="chip chip-alt">{esc(c)}</span>'
                           for c in b["data_classes"][:8])
    added = b["added_date"].strftime("%d %b %Y") if b["added_date"] else "Unknown"

    return f"""
        <div class="apt-card row">{rank_html}
          <div class="apt-body">
            <div class="apt-top">
              <div class="apt-name plain">{esc(b['name'])} <span class="domain-note">({esc(b['domain'])})</span></div>
              <div class="apt-badges">{verified}{sensitive}</div>
            </div>
            <div class="apt-desc">{esc(b['description'])}</div>
            <div class="apt-subsection" style="margin-top:6px;">
              <div class="chip-list">{classes_html}</div>
            </div>
            <div class="breach-meta">
              <span>\U0001f4a5 {b['pwn_count']:,} accounts</span>
              <span>\U0001f4c5 Breach occurred: {esc(b['breach_date'])}</span>
              <span>\U0001f4e5 Added to HIBP: {esc(added)}</span>
            </div>
          </div>
        </div>
"""


def ttp_render(out_path, apt_records, recent_breaches, top_year_breaches):
    body = stat_grid([
        ("\U0001f3ad APT Groups Tracked", len(apt_records)),
        ("\U0001f5e1\ufe0f TTPs Catalogued", sum(r["technique_total"] for r in apt_records)),
        ("\U0001f6a8 Breaches (7d)", len(recent_breaches)),
        ("\U0001f4db Top Breaches (365d)", len(top_year_breaches)),
    ])

    body += section_html(
        "\U0001f3ad Active APT Groups, Campaigns &amp; TTPs",
        f"top {len(apt_records)} by ATT&amp;CK update recency",
        "".join(apt_card(r) for r in apt_records)
        or empty_state("Could not load the MITRE ATT&amp;CK dataset \u2014 "
                       "check connectivity and try again."),
        note=('No free feed publishes real-time "this APT is active right now" status, so '
              "groups here are ranked by how recently MITRE ATT&amp;CK updated their entry "
              "(a proxy for which groups are being actively tracked/researched), with "
              'technique breadth as a tiebreaker. Campaigns marked "\u26a0\ufe0f" are informal '
              "mentions mined from the group's own description text, not formally modeled "
              "ATT&amp;CK Campaign objects \u2014 not every group has the latter."))

    body += section_html(
        "\U0001f6a8 Recent Breaches \u2014 Last 7 Days", f"{len(recent_breaches)} breaches",
        "".join(breach_card(b) for b in recent_breaches)
        or empty_state("No breaches were added to HIBP in the last 7 days."),
        note=('"Recent" is based on when Have I Been Pwned added the breach to its database, '
              "the closest available proxy for public disclosure \u2014 the breach itself may "
              'have occurred earlier (see "Breach occurred" vs "Added to HIBP" on each card).'))

    body += section_html(
        f"\U0001f4db Top {TOP_N_YEARLY_BREACHES} Breaches \u2014 Last 365 Days",
        "ranked by accounts affected",
        "".join(breach_card(b, show_rank=i) for i, b in enumerate(top_year_breaches))
        or empty_state("No breaches were added to HIBP in the last 365 days."))

    html = render_page(
        "ttp", "Threat Actor &amp; Breach Intelligence", "Threat Intelligence Digest",
        "\U0001f3ad Threat Actor &amp; Breach Watch",
        f"Generated {generated_line()} \u00b7 data via MITRE ATT&amp;CK &amp; Have I Been Pwned",
        body,
        "Generated by Threat Actor &amp; Breach Watch \u00b7 Data sourced from "
        "MITRE ATT&amp;CK and Have I Been Pwned")
    out_path.write_text(html, encoding="utf-8")
    return out_path


def ttp_main(log):
    now = datetime.now(timezone.utc)
    session = make_session(pool_size=4)

    log("Loading MITRE ATT&CK Enterprise dataset (tens of MB; cached for 7 days)...")
    bundle = cached_json(session, ATTACK_STIX_URL, "attack_enterprise.json",
                         max_age_hours=7 * 24, log=log, timeout=180)

    apt_records = []
    if bundle:
        log("Building APT group / campaign / TTP records...")
        apt_records = build_apt_records(bundle)
    else:
        log("  Skipping APT section - dataset unavailable.")

    log("Loading breach catalog from Have I Been Pwned (cached for 6 hours)...")
    raw_breaches = cached_json(session, HIBP_BREACHES_URL, "hibp_breaches.json",
                               max_age_hours=6, log=log, timeout=60) or []
    breaches = [r for b in raw_breaches
                if (r := build_breach_record(b))["added_date"] is not None]

    recent = sorted((b for b in breaches
                     if b["added_date"] >= now - timedelta(days=7)),
                    key=lambda b: b["added_date"], reverse=True)
    yearly = sorted((b for b in breaches
                     if b["added_date"] >= now - timedelta(days=365)),
                    key=lambda b: b["pwn_count"], reverse=True)

    log("Generating report...")
    return ttp_render(RUN_DIR / "threat_actors.html", apt_records, recent,
                      yearly[:TOP_N_YEARLY_BREACHES])


# ===========================================================================
# Index page, back-button injection, runner
# ===========================================================================

BACK_BUTTON = (
    '<a href="index.html" style="position:fixed; top:18px; left:18px; z-index:9999; '
    'display:inline-flex; align-items:center; gap:6px; padding:8px 16px; '
    'border-radius:999px; background:rgba(15,15,20,0.85); color:#f5f5f5; '
    "font-family:'JetBrains Mono', monospace; font-size:12px; font-weight:600; "
    'text-decoration:none; border:1px solid rgba(255,255,255,0.15); '
    'backdrop-filter:blur(6px);">\u2190 Back to Index</a>\n'
)


def inject_back_button(html_path):
    """Adds a fixed 'Back to Index' button before </body>. Inline styles
    only, so it can't clash with a report's own CSS."""
    try:
        html = html_path.read_text(encoding="utf-8")
        if "</body>" in html:
            html = html.replace("</body>", BACK_BUTTON + "</body>", 1)
        else:
            html += BACK_BUTTON
        html_path.write_text(html, encoding="utf-8")
    except OSError as e:
        print(f"  ! Could not inject back-button into {html_path}: {e}")


def build_index_html(results):
    """results: dict of key -> (path_or_None, error_or_None)."""
    cards = []
    for key, filename, title, color, blurb in REPORTS:
        path, error = results.get(key, (None, "Not run"))
        if path is not None:
            cards.append(f"""
        <a class="report-card" href="{filename}" style="border-left-color:{color};">
          <div class="report-title" style="color:{color};">{esc(title)}</div>
          <div class="report-blurb">{esc(blurb)}</div>
          <div class="report-cta" style="color:{color};">Open report \u2192</div>
        </a>
""")
        else:
            cards.append(f"""
        <div class="report-card report-card-disabled" style="border-left-color:{color};">
          <div class="report-title" style="color:{color};">{esc(title)}</div>
          <div class="report-blurb">{esc(blurb)}</div>
          <div class="report-cta report-cta-error">\u26a0 Generation failed: {esc(error)}</div>
        </div>
""")

    body = f'  <div class="hub-grid">\n{"".join(cards)}\n  </div>'
    html = render_page(
        "hub", f"Cyber Intel Suite \u2014 {RUN_TIMESTAMP}", "Cyber Intel Suite",
        "\U0001f6e1\ufe0f Report Hub",
        f"Run {RUN_TIMESTAMP} \u00b7 generated {generated_line()}",
        body,
        "Cyber Intel Suite \u00b7 CVE Watch \u00b7 Ransomware Watch \u00b7 "
        "Cyber News Wire \u00b7 Threat Actor &amp; Breach Watch",
        container_max=960)
    index_path = RUN_DIR / "index.html"
    index_path.write_text(html, encoding="utf-8")
    return index_path


def run_module(key, label, main_func):
    """Runs one module and collects its log lines in a private buffer.

    v1 used contextlib.redirect_stdout here, which swaps the process-global
    stdout - with four threads, log lines landed in whichever buffer was
    installed last and restoration order could misattribute entire blocks.
    A plain per-module list has no shared state, so logs stay correct."""
    lines = []

    def log(msg):
        lines.append(str(msg))

    try:
        path = Path(main_func(log))
        inject_back_button(path)
        result = (path, None)
    except Exception as e:
        result = (None, f"{type(e).__name__}: {e}")
    return key, label, result, "\n".join(lines)


def parse_args():
    parser = argparse.ArgumentParser(description="Cyber Intel Suite report generator")
    parser.add_argument("--modules", default="cve,rsw,news,ttp",
                        help="Comma-separated subset of: cve,rsw,news,ttp")
    parser.add_argument("--fresh", action="store_true",
                        help="Ignore on-disk caches and re-download everything")
    parser.add_argument("--no-browser", action="store_true",
                        help="Don't open the index page when done")
    return parser.parse_args()


def main():
    global FORCE_FRESH
    args = parse_args()
    FORCE_FRESH = args.fresh

    RUN_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    all_jobs = {
        "cve": ("Critical CVE Watch", cve_main),
        "rsw": ("Ransomware Watch", rsw_main),
        "news": ("Cyber News Wire", news_main),
        "ttp": ("Threat Actor & Breach Watch", ttp_main),
    }
    wanted = [m.strip() for m in args.modules.split(",") if m.strip()]
    unknown = [m for m in wanted if m not in all_jobs]
    if unknown:
        raise SystemExit(f"Unknown module(s): {', '.join(unknown)}. "
                         f"Valid: {', '.join(all_jobs)}")
    jobs = [(k, *all_jobs[k]) for k in wanted]

    print(f"Cyber Intel Suite - run folder: {RUN_DIR}")
    if not API_KEYS and not os.environ.get("NVD_API_KEY"):
        print("  (api_keys.txt not found - keyed sources run unauthenticated: "
              "slower / lower rate limits.)")
    print(f"Running {len(jobs)} report generator(s) concurrently...\n")

    started = time.monotonic()
    results = {}
    with ThreadPoolExecutor(max_workers=len(jobs)) as executor:
        futures = [executor.submit(run_module, key, label, fn)
                   for key, label, fn in jobs]
        for future in as_completed(futures):
            key, label, result, output = future.result()
            print(f"\n{'=' * 60}\n{label}\n{'=' * 60}")
            if output.strip():
                print(output.rstrip())
            path, error = result
            print(f"  Done -> {path}" if path else f"  ! {label} failed: {error}")
            results[key] = result

    print(f"\n{'=' * 60}\nBuilding index page...\n{'=' * 60}")
    index_path = build_index_html(results)

    ok = sum(1 for path, _ in results.values() if path is not None)
    print(f"\n{ok}/{len(results)} reports generated successfully "
          f"in {time.monotonic() - started:.1f}s.")
    print(f"Index: {index_path}")

    if not args.no_browser:
        # as_uri() builds a correct file:// URL on every OS (v1's string
        # concatenation broke on Windows paths).
        webbrowser.open(index_path.resolve().as_uri())


if __name__ == "__main__":
    main()