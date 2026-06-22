"""
app.py
======
Flask front-end and JSON API for the Web Scraper & Site Auditor.

Architecture
------------
Scans are long-running and must not block HTTP requests, so each scan executes
in its own **worker thread**. Because Playwright's crawler is ``async``, every
worker thread hosts a dedicated ``asyncio`` event loop (created by
``asyncio.run``) that drives :class:`scraper.SiteCrawler`.

A process-wide :class:`ScanManager` keeps the in-memory registry of scans. Each
:class:`ScanJob` is guarded by a lock so the background worker and the polling
HTTP handlers can safely touch the same state concurrently. The browser UI polls
``/api/scan/<id>/status`` to render the live progress bar and the streaming list
of issues - no external broker (Redis/Celery) is required.

Routes
------
``GET  /``                       - the scan-configuration form (index.html).
``POST /api/scan``               - create + start a scan, returns ``{"id": ...}``.
``GET  /scan/<id>``              - live + final report view (report.html).
``GET  /api/scan/<id>/status``   - JSON status used for polling.
``POST /api/scan/<id>/cancel``   - request cancellation of a running scan.
``GET  /api/scan/<id>/export``   - download the full report as JSON.
"""

from __future__ import annotations

import asyncio
import json
import queue
import re
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlparse

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    render_template,
    request,
    stream_with_context,
    url_for,
)

from analyzers import SEVERITY_ORDER, Issue, compute_category_ranks, compute_risk
from crawler import CrawlConfig, PageResult, SiteCrawler
from report_pdf import build_pdf_report

app = Flask(__name__)

# Cap how many issues / pages we retain per scan to keep memory bounded even on
# very large sites. The UI streams the most recent items.
MAX_RETAINED_ISSUES = 5_000
MAX_RETAINED_PAGES = 2_000

# Hard ceilings applied to user input to keep a single scan well-behaved.
DEPTH_CEILING = 6
PAGES_CEILING = 200

# The audit modules the UI can toggle. Order drives the checkbox layout.
AVAILABLE_MODULES = ["links", "security", "accessibility", "privacy", "content", "seo", "bugs"]

# Statuses after which a scan produces no further events.
TERMINAL_STATES = {"completed", "failed", "cancelled"}

# Basic hostname / IP shape used to reject obviously invalid targets.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9_-]{1,63}\.)*[A-Za-z0-9_-]{1,63}$"
)


# ---------------------------------------------------------------------------
# Scan job state
# ---------------------------------------------------------------------------
@dataclass
class ScanJob:
    """Thread-safe container for a single scan's configuration and results."""

    id: str
    start_url: str
    config: CrawlConfig
    status: str = "pending"               # pending|running|completed|failed|cancelled
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    error: str = ""
    progress: dict = field(default_factory=dict)
    issues: List[dict] = field(default_factory=list)
    pages: List[dict] = field(default_factory=list)
    _cancel: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    # SSE fan-out: each connected dashboard registers a queue here.
    _subscribers: List["queue.Queue"] = field(default_factory=list, repr=False)

    # -- mutators called from the worker thread ----------------------------
    def add_issue(self, issue: Issue) -> None:
        with self._lock:
            if len(self.issues) < MAX_RETAINED_ISSUES:
                data = issue.to_dict()
                self.issues.append(data)
                self._publish_locked({"type": "issue", "issue": data})

    def add_page(self, page: PageResult) -> None:
        with self._lock:
            if len(self.pages) < MAX_RETAINED_PAGES:
                self.pages.append(page.summary())

    def set_progress(self, progress: dict) -> None:
        with self._lock:
            self.progress = progress
            self._publish_locked({
                "type": "progress",
                "progress": dict(progress),
                "counts": self._counts_locked(),
                "risk": compute_risk(self.issues),
                "issue_total": len(self.issues),
                "elapsed": self._elapsed_locked(),
            })

    def mark(self, status: str, error: str = "") -> None:
        with self._lock:
            self.status = status
            if error:
                self.error = error
            if status == "running" and self.started_at is None:
                self.started_at = time.time()
            if status in ("completed", "failed", "cancelled"):
                self.finished_at = time.time()
            self._publish_locked({
                "type": "status",
                "status": self.status,
                "error": self.error,
                "counts": self._counts_locked(),
                "risk": compute_risk(self.issues),
                "issue_total": len(self.issues),
                "elapsed": self._elapsed_locked(),
            })
            if status in ("completed", "failed", "cancelled"):
                self._publish_locked({"type": "end"})

    # -- Server-Sent Events fan-out ----------------------------------------
    def subscribe(self) -> "queue.Queue":
        """Register a new SSE listener and seed it with a full snapshot."""
        listener: "queue.Queue" = queue.Queue(maxsize=2000)
        with self._lock:
            listener.put_nowait({
                "type": "snapshot",
                "status": self.status,
                "error": self.error,
                "progress": dict(self.progress),
                "counts": self._counts_locked(),
                "risk": compute_risk(self.issues),
                "issues": list(self.issues),
                "issue_total": len(self.issues),
                "elapsed": self._elapsed_locked(),
            })
            # A late subscriber on an already-finished scan gets an immediate end.
            if self.status in ("completed", "failed", "cancelled"):
                listener.put_nowait({"type": "end"})
            self._subscribers.append(listener)
        return listener

    def unsubscribe(self, listener: "queue.Queue") -> None:
        with self._lock:
            if listener in self._subscribers:
                self._subscribers.remove(listener)

    def _publish_locked(self, event: dict) -> None:
        """Push an event to every subscriber (caller must hold ``_lock``)."""
        dead = []
        for listener in self._subscribers:
            try:
                listener.put_nowait(event)
            except queue.Full:
                dead.append(listener)  # slow/abandoned client - drop it
        for listener in dead:
            self._subscribers.remove(listener)

    # -- cancellation ------------------------------------------------------
    def request_cancel(self) -> None:
        with self._lock:
            self._cancel = True

    def is_cancelled(self) -> bool:
        with self._lock:
            return self._cancel

    # -- read helpers used by the HTTP handlers ----------------------------
    def _counts_locked(self) -> dict:
        """Aggregate issue counts by severity and category (lock held)."""
        by_severity: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        for item in self.issues:
            by_severity[item["severity"]] = by_severity.get(item["severity"], 0) + 1
            by_category[item["category"]] = by_category.get(item["category"], 0) + 1
        return {"by_severity": by_severity, "by_category": by_category, "total": len(self.issues)}

    def status_payload(self, issue_offset: int = 0) -> dict:
        """Snapshot for the polling endpoint.

        ``issue_offset`` lets the client fetch only newly discovered issues so
        the live view can append rather than re-render everything each tick.
        """
        with self._lock:
            new_issues = self.issues[issue_offset:] if issue_offset < len(self.issues) else []
            return {
                "id": self.id,
                "status": self.status,
                "start_url": self.start_url,
                "error": self.error,
                "progress": dict(self.progress),
                "counts": self._counts_locked(),
                "risk": compute_risk(self.issues),
                "issue_total": len(self.issues),
                "page_total": len(self.pages),
                "new_issues": new_issues,
                "elapsed": self._elapsed_locked(),
                "config": {
                    "max_depth": self.config.max_depth,
                    "max_pages": self.config.max_pages,
                    "modules": self.config.modules,
                },
            }

    def full_report(self) -> dict:
        """Complete, ordered report used for the export endpoint."""
        with self._lock:
            ordered = sorted(
                self.issues,
                key=lambda i: (SEVERITY_ORDER.get(i["severity"], 9), i["category"], i["url"]),
            )
            return {
                "id": self.id,
                "start_url": self.start_url,
                "status": self.status,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "config": {
                    "max_depth": self.config.max_depth,
                    "max_pages": self.config.max_pages,
                    "modules": self.config.modules,
                },
                "summary": self._counts_locked(),
                "risk": compute_risk(ordered),
                "category_ranks": compute_category_ranks(ordered, len(self.pages)),
                "elapsed_seconds": self._elapsed_locked(),
                "pages": list(self.pages),
                "issues": ordered,
            }

    def _elapsed_locked(self) -> float:
        if self.started_at is None:
            return 0.0
        end = self.finished_at or time.time()
        return round(end - self.started_at, 1)


# ---------------------------------------------------------------------------
# Scan manager - owns the worker threads and the job registry
# ---------------------------------------------------------------------------
class ScanManager:
    """Creates, starts, tracks and cancels scans."""

    def __init__(self) -> None:
        self._jobs: Dict[str, ScanJob] = {}
        self._lock = threading.Lock()

    def create(self, start_url: str, config: CrawlConfig) -> ScanJob:
        job = ScanJob(id=uuid.uuid4().hex, start_url=start_url, config=config)
        with self._lock:
            self._jobs[job.id] = job
        return job

    def get(self, scan_id: str) -> Optional[ScanJob]:
        with self._lock:
            return self._jobs.get(scan_id)

    def start(self, job: ScanJob) -> None:
        worker = threading.Thread(target=self._run, args=(job,), daemon=True)
        worker.start()

    # -- worker body -------------------------------------------------------
    def _run(self, job: ScanJob) -> None:
        """Thread entry point: spin up an event loop and run the crawler."""
        # Playwright launches a browser subprocess; on Windows that requires the
        # Proactor event-loop policy (the default for the main thread, but it
        # must be set explicitly for worker threads).
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

        job.mark("running")
        crawler = SiteCrawler(
            start_url=job.start_url,
            config=job.config,
            on_progress=job.set_progress,
            on_issue=job.add_issue,
            on_page=job.add_page,
            should_stop=job.is_cancelled,
        )
        try:
            asyncio.run(crawler.crawl())
            job.mark("cancelled" if job.is_cancelled() else "completed")
        except Exception as exc:  # noqa: BLE001 - surface any crawl failure to the UI
            job.mark("failed", error=f"{type(exc).__name__}: {exc}")


scan_manager = ScanManager()


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------
def _clamp(value, low, high, default):
    """Coerce ``value`` to an int within ``[low, high]`` (fallback to default)."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


def _normalise_start_url(raw: str) -> Optional[str]:
    """Validate and normalise the target URL; return ``None`` if unusable."""
    raw = (raw or "").strip()
    # Reject empties and anything containing raw whitespace (invalid in a URL).
    if not raw or any(ch.isspace() for ch in raw):
        return None
    if not urlparse(raw).scheme:
        raw = "https://" + raw
    parts = urlparse(raw)
    # Only http(s) targets are accepted.
    if parts.scheme not in ("http", "https"):
        return None
    host = parts.hostname or ""
    if not host:
        return None
    if host == "localhost":
        return raw
    # A real host must look like a domain or IP (letters/digits/dots/hyphens)
    # and contain at least one dot.
    if "." not in host or not _HOSTNAME_RE.match(host):
        return None
    return raw


def _build_config(payload: dict) -> CrawlConfig:
    """Translate a request payload into a validated :class:`CrawlConfig`."""
    requested = payload.get("modules")
    if isinstance(requested, list):
        modules = [m for m in requested if m in AVAILABLE_MODULES]
    else:
        # Form-style: a module is enabled when its key is truthy.
        modules = [m for m in AVAILABLE_MODULES if str(payload.get(m, "")).lower()
                   in ("1", "true", "on", "yes")]
    if not modules:
        modules = list(AVAILABLE_MODULES)  # default: run everything

    return CrawlConfig(
        max_depth=_clamp(payload.get("max_depth"), 0, DEPTH_CEILING, 2),
        max_pages=_clamp(payload.get("max_pages"), 1, PAGES_CEILING, 25),
        modules=modules,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    """Render the scan-configuration form."""
    return render_template("index.html", modules=AVAILABLE_MODULES,
                           depth_ceiling=DEPTH_CEILING, pages_ceiling=PAGES_CEILING)


@app.route("/api/scan", methods=["POST"])
def api_create_scan():
    """Validate input, create a scan job and start the worker thread."""
    payload = request.get_json(silent=True) or request.form.to_dict()
    start_url = _normalise_start_url(payload.get("url", ""))
    if not start_url:
        return jsonify({"error": "Please provide a valid http(s) URL."}), 400

    config = _build_config(payload)
    job = scan_manager.create(start_url, config)
    scan_manager.start(job)
    return jsonify({
        "id": job.id,
        "redirect": url_for("scan_report", scan_id=job.id),
    }), 202


@app.route("/scan/<scan_id>")
def scan_report(scan_id: str):
    """Single page that shows live progress and, once done, the full report."""
    job = scan_manager.get(scan_id)
    if job is None:
        abort(404)
    return render_template("dashboard.html", scan_id=scan_id, start_url=job.start_url)


@app.route("/api/scan/<scan_id>/status")
def api_scan_status(scan_id: str):
    """Polling endpoint (SSE fallback) that powers the live dashboard."""
    job = scan_manager.get(scan_id)
    if job is None:
        return jsonify({"error": "Scan not found."}), 404
    # The client passes how many issues it already has so we only return new ones.
    offset = _clamp(request.args.get("since"), 0, MAX_RETAINED_ISSUES, 0)
    return jsonify(job.status_payload(issue_offset=offset))


@app.route("/api/scan/<scan_id>/stream")
def api_scan_stream(scan_id: str):
    """Server-Sent Events stream of live progress, issues and risk updates."""
    job = scan_manager.get(scan_id)
    if job is None:
        return jsonify({"error": "Scan not found."}), 404

    def event_stream():
        listener = job.subscribe()
        try:
            while True:
                try:
                    event = listener.get(timeout=15)
                except queue.Empty:
                    # Comment line keeps proxies / browsers from timing out.
                    yield ": keep-alive\n\n"
                    if job.status in TERMINAL_STATES:
                        break
                    continue
                if event.get("type") == "end":
                    yield "event: end\ndata: {}\n\n"
                    break
                yield f"data: {json.dumps(event)}\n\n"
        finally:
            job.unsubscribe(listener)

    return Response(
        stream_with_context(event_stream()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx buffering for SSE
            "Connection": "keep-alive",
        },
    )


@app.route("/api/scan/<scan_id>/cancel", methods=["POST"])
def api_scan_cancel(scan_id: str):
    """Request cooperative cancellation of a running scan."""
    job = scan_manager.get(scan_id)
    if job is None:
        return jsonify({"error": "Scan not found."}), 404
    job.request_cancel()
    return jsonify({"id": scan_id, "status": "cancelling"})


@app.route("/api/scan/<scan_id>/export")
def api_scan_export(scan_id: str):
    """Return the complete report as a downloadable JSON document."""
    job = scan_manager.get(scan_id)
    if job is None:
        return jsonify({"error": "Scan not found."}), 404
    report = job.full_report()
    response = jsonify(report)
    response.headers["Content-Disposition"] = (
        f"attachment; filename=compliance-audit-{scan_id[:8]}.json"
    )
    return response


@app.route("/api/scan/<scan_id>/report.pdf")
def api_scan_pdf(scan_id: str):
    """Generate and download an in-depth PDF compliance report."""
    job = scan_manager.get(scan_id)
    if job is None:
        abort(404)
    report = job.full_report()
    try:
        pdf_bytes = build_pdf_report(report)
    except Exception as exc:  # noqa: BLE001 - surface generation failures cleanly
        return jsonify({"error": f"PDF generation failed: {exc}"}), 500
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=compliance-audit-{scan_id[:8]}.pdf"
        },
    )


@app.errorhandler(404)
def not_found(_err):
    return render_template("base.html", not_found=True), 404


if __name__ == "__main__":
    # Threaded dev server. For production use a real WSGI server, e.g.:
    #   waitress-serve --listen=0.0.0.0:5000 app:app
    app.run(host="127.0.0.1", port=5000, threaded=True, debug=False)
