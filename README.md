# SiteAuditor — Web Scraper & Site Auditor

A full-stack web application that crawls a target website and performs a
comprehensive audit of every page: **dead links, security, accessibility,
content quality and JavaScript runtime bugs**. It ships with a modern,
real-time dashboard built with Flask, Tailwind CSS and vanilla JavaScript.

> ⚠️ **Only scan websites you own or are explicitly authorised to test.**

---

## Features

| Module | What it checks |
| --- | --- |
| **Dead Links** | 404s, unreachable hosts, broken external links, redirect loops |
| **Security** | Missing security headers, mixed (HTTP-on-HTTPS) content, exposed API keys / secrets / env vars, sensitive admin paths |
| **Accessibility** | Missing `alt` text, missing `lang`, heading-order problems, vague link text, unlabeled form controls |
| **Content** | Duplicate / over-long titles & meta descriptions, thin content, readability (Flesch), placeholder text, title↔H1 mismatch, LLM-ready contradiction hook |
| **Bugs** | Uncaught JS exceptions, `console.error` output and failed network requests (captured live via Playwright) |

* **Asynchronous, non-blocking crawler** — each scan runs in a worker thread
  hosting its own `asyncio` event loop driving Playwright.
* **Live dashboard** — progress bar, streaming issues, severity/category
  filters and full-text search, with one-click **JSON export**.
* No external broker required (no Redis/Celery) — in-memory job manager.

## Tech stack

* **Backend:** Python, Flask, threaded job manager + `asyncio`
* **Scraping:** Playwright (headless Chromium) + BeautifulSoup4 + aiohttp
* **Frontend:** Jinja2 templates, Tailwind CSS (CDN), Fetch-API polling

---

## Project structure

```
.
├── app.py            # Flask app: routes, JSON API, threaded ScanManager
├── scraper.py        # Async crawling engine (Playwright + BeautifulSoup + aiohttp)
├── analyzers.py      # Security / Accessibility / Content / Bug audit modules
├── requirements.txt
└── templates/
    ├── base.html     # Shared layout (Tailwind, nav, footer)
    ├── index.html    # Scan-configuration form
    └── report.html   # Live progress + filterable results dashboard
```

---

## Setup

```powershell
# 1. Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1            # Windows PowerShell
# source .venv/bin/activate             # macOS / Linux

# 2. Install dependencies
pip install -r requirements.txt

# 3. Install the headless browser Playwright drives
python -m playwright install chromium
```

## Run

```powershell
# Development server
python app.py
# -> http://127.0.0.1:5000

# Production (Waitress WSGI server)
waitress-serve --listen=127.0.0.1:5000 app:app
```

Open the dashboard, enter a URL, choose the crawl depth / page limit and the
modules to run, then click **Start Audit** to watch results stream in live.

---

## REST API

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/api/scan` | Start a scan. Body: `{ "url", "max_depth", "max_pages", "modules": [...] }` → `{ "id", "redirect" }` |
| `GET` | `/api/scan/<id>/status?since=<n>` | Poll status, counts and new issues |
| `POST` | `/api/scan/<id>/cancel` | Request cancellation |
| `GET` | `/api/scan/<id>/export` | Download the full report as JSON |

---

## Notes & safety

* The crawler stays on the target's registrable domain (subdomains included)
  and honours the configured depth and page ceilings.
* `ignore_https_errors` / non-verifying link checks let the auditor probe sites
  with invalid certificates without crashing — adjust in `scraper.py` if you
  need strict TLS verification.
* All scraped strings are rendered into the dashboard as **text** (never HTML),
  preventing stored-XSS from a malicious target page.
* The optional LLM "contradicting information" analysis is wired as a no-op hook
  (`ContentAnalyzer.llm_review`) so the tool runs fully offline by default.

TO RUN:
.\.venv\Scripts\python.exe app.py