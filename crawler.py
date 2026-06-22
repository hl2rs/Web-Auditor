"""
crawler.py
==========
Asynchronous crawling orchestrator for the Compliance Risk Auditor.

Responsibilities
----------------
* Render each page with **Playwright** (headless Chromium) so that JavaScript
  executes and runtime/console errors and failed network requests are captured.
* Capture privacy signals: every sub-resource **request URL** and all **cookies**
  dropped on load (cookies are cleared before each navigation so findings are
  unambiguously *pre-consent*).
* Measure interactive **target sizes** in the live page for WCAG 2.2 SC 2.5.8.
* Parse the rendered HTML with **BeautifulSoup4** for fast DOM analysis.
* Discover internal links and crawl breadth-first up to a configurable depth /
  page limit, honouring a concurrency budget and timeout protections.
* Verify every discovered link (internal *and* external) with an asynchronous
  **aiohttp** client to find 404s, unreachable hosts and redirect loops.
* Feed each page through the pluggable analyzers defined in :mod:`analyzers`,
  annotate every finding with its legal/financial mapping, and run a final
  whole-corpus contradiction pass.

The crawler is deliberately decoupled from the web layer: it communicates
progress and findings exclusively through callbacks supplied by the caller
(``on_progress`` / ``on_issue`` / ``on_page`` / ``should_stop``), so it can be
driven from Flask, a CLI, or tests without modification.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urldefrag, urljoin, urlparse, urlunparse

import aiohttp
from bs4 import BeautifulSoup
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from playwright.async_api import async_playwright

from analyzers import (
    ANALYZER_REGISTRY,
    CATEGORY_DEAD_LINKS,
    SEVERITY_CRITICAL,
    SEVERITY_WARNING,
    AnalyzerContext,
    Issue,
    annotate_legal,
)

# Schemes / prefixes that are never crawled or link-checked.
_SKIP_PREFIXES = ("#", "mailto:", "tel:", "javascript:", "data:", "blob:", "ftp:", "sms:")

# In-page script (run via ``page.evaluate``) that measures interactive controls
# and returns those smaller than the WCAG 2.2 SC 2.5.8 minimum of 24x24 CSS px.
# Inline links flowing inside surrounding text are exempt under the SC and are
# skipped to avoid false positives.
_TARGET_SIZE_JS = r"""
() => {
  const selector = 'a[href], button, input:not([type=hidden]), select, ' +
                   'textarea, [role="button"], [onclick]';
  const out = [];
  for (const el of document.querySelectorAll(selector)) {
    if (el.disabled) continue;
    const rect = el.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) continue;   // not rendered
    if (rect.width >= 24 && rect.height >= 24) continue;    // meets minimum
    if (el.tagName === 'A') {
      const p = el.parentElement;
      if (p) {
        const parentLen = (p.textContent || '').trim().length;
        const selfLen = (el.textContent || '').trim().length;
        if (parentLen - selfLen > 1) continue;             // inline-in-text exempt
      }
    }
    let label = (el.getAttribute('aria-label') || el.textContent ||
                 el.getAttribute('name') || el.getAttribute('title') ||
                 el.tagName || '').replace(/\s+/g, ' ').trim().slice(0, 60);
    out.push({ label: label || el.tagName,
               w: Math.round(rect.width), h: Math.round(rect.height) });
    if (out.length >= 50) break;
  }
  return out;
}
"""


# ---------------------------------------------------------------------------
# Configuration & result data structures
# ---------------------------------------------------------------------------
@dataclass
class CrawlConfig:
    """User-tunable crawl parameters (validated/built in :mod:`app`)."""

    max_depth: int = 2
    max_pages: int = 25
    # Enabled modules. Analyzer keys come from ``ANALYZER_REGISTRY``; the special
    # key ``"links"`` toggles the dead-link checker.
    modules: List[str] = field(
        default_factory=lambda: ["security", "accessibility", "content", "bugs", "links"]
    )
    page_timeout_ms: int = 25_000      # navigation timeout per page
    settle_ms: int = 2_500             # extra wait for late JS / network-idle
    link_timeout_s: float = 12.0       # per-request timeout for link checks
    link_concurrency: int = 12         # simultaneous link checks
    max_redirects: int = 10            # redirect cap before flagging a loop
    max_links_check: int = 750         # safety cap on number of links verified
    user_agent: str = (
        "Mozilla/5.0 (compatible; SiteAuditorBot/1.0; +https://example.local/bot)"
    )


@dataclass
class PageResult:
    """Outcome of rendering and analyzing a single page."""

    url: str
    final_url: str
    status: int
    depth: int
    title: str = ""
    load_time_ms: int = 0
    ok: bool = False
    error: str = ""
    internal_links: List[str] = field(default_factory=list)
    console_errors: List[dict] = field(default_factory=list)
    page_errors: List[dict] = field(default_factory=list)
    failed_requests: List[dict] = field(default_factory=list)

    def summary(self) -> dict:
        """Lightweight, JSON-serialisable view for the dashboard."""
        return {
            "url": self.final_url,
            "status": self.status,
            "depth": self.depth,
            "title": self.title,
            "load_time_ms": self.load_time_ms,
            "ok": self.ok,
            "error": self.error,
        }


@dataclass
class LinkCheckResult:
    """Result of verifying a single hyperlink."""

    url: str
    status: int = 0                 # 0 == connection failed, -1 == redirect loop
    error: str = ""
    is_loop: bool = False
    redirect_chain: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------
def normalize_url(url: str) -> str:
    """Canonicalise a URL so the crawler does not visit duplicates.

    Drops the fragment, lower-cases scheme/host, removes default ports and any
    trailing slash (except for the root path), and preserves the query string.
    """
    url, _frag = urldefrag(url)
    parts = urlparse(url)
    scheme = parts.scheme.lower()
    netloc = parts.netloc.lower()
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]
    path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return urlunparse((scheme, netloc, path, parts.params, parts.query, ""))


def registrable_host(host: str) -> str:
    """Return a comparable host with the leading ``www.`` removed."""
    host = (host or "").lower().split(":")[0]
    return host[4:] if host.startswith("www.") else host


# ---------------------------------------------------------------------------
# The crawler
# ---------------------------------------------------------------------------
class SiteCrawler:
    """Breadth-first crawler that renders, analyses and link-checks a site."""

    def __init__(
        self,
        start_url: str,
        config: CrawlConfig,
        on_progress: Optional[Callable[[dict], None]] = None,
        on_issue: Optional[Callable[[Issue], None]] = None,
        on_page: Optional[Callable[[PageResult], None]] = None,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> None:
        self.start_url = _ensure_scheme(start_url)
        self.config = config
        self.on_progress = on_progress
        self.on_issue = on_issue
        self.on_page = on_page
        self.should_stop = should_stop or (lambda: False)

        self.base_root = registrable_host(urlparse(self.start_url).netloc)

        # Instantiate the requested analyzers once so cross-page state persists.
        self.analyzers = [
            ANALYZER_REGISTRY[key]()
            for key in config.modules
            if key in ANALYZER_REGISTRY
        ]
        self.check_links_enabled = "links" in config.modules

        # Runtime state -----------------------------------------------------
        self.pages_scanned = 0
        self.queue_size = 0
        self.links_checked = 0
        self.links_total = 0
        self.phase = "starting"
        self.current_url = ""
        # normalized URL -> HTTP status observed while crawling.
        self.page_status: Dict[str, int] = {}
        # normalized target URL -> set of source pages that link to it.
        self.discovered_links: Dict[str, Set[str]] = defaultdict(set)
        self._issue_keys: Set[Tuple] = set()

    # -- public entry point -------------------------------------------------
    async def crawl(self) -> None:
        """Run the full crawl + link-check pipeline."""
        self._emit_progress(phase="starting", current_url=self.start_url)
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                # ``--no-sandbox`` keeps Chromium happy inside containers / CI.
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            context = await browser.new_context(
                ignore_https_errors=True,         # audit sites with bad certs too
                user_agent=self.config.user_agent,
                viewport={"width": 1366, "height": 900},
            )
            try:
                await self._crawl_pages(context)
            finally:
                # Always tear the browser down, even on error/cancellation.
                await context.close()
                await browser.close()

        # Whole-corpus finalisation pass (e.g. cross-page LLM contradiction
        # detection) for any analyzer that opts in via a ``finalize()`` method.
        if not self.should_stop():
            self._run_finalizers()

        if self.check_links_enabled and not self.should_stop():
            await self._check_links()

        self._emit_progress(phase="completed")

    def _run_finalizers(self) -> None:
        for analyzer in self.analyzers:
            finalize = getattr(analyzer, "finalize", None)
            if not callable(finalize):
                continue
            try:
                for issue in finalize():
                    self._add_issue(issue)
            except Exception:
                pass  # a finalizer must never break the scan

    # -- breadth-first page crawl ------------------------------------------
    async def _crawl_pages(self, context) -> None:
        start_norm = normalize_url(self.start_url)
        queue: deque = deque([(self.start_url, 0)])
        enqueued: Set[str] = {start_norm}
        # Bound queue growth so a huge site cannot exhaust memory.
        queue_cap = max(self.config.max_pages * 10, 200)

        while queue:
            if self.should_stop():
                self.phase = "cancelled"
                return
            if self.pages_scanned >= self.config.max_pages:
                break

            url, depth = queue.popleft()
            self.queue_size = len(queue)
            self._emit_progress(phase="crawling", current_url=url)

            result = await self._process_page(context, url, depth)
            self.pages_scanned += 1
            if self.on_page:
                self.on_page(result)

            # Queue newly discovered internal links within the depth budget.
            if result.ok and depth < self.config.max_depth:
                for link in result.internal_links:
                    norm = normalize_url(link)
                    if norm in enqueued or norm in self.page_status:
                        continue
                    if len(enqueued) >= queue_cap:
                        break
                    enqueued.add(norm)
                    queue.append((link, depth + 1))

            self._emit_progress(phase="crawling")

    # -- render + analyse a single page ------------------------------------
    async def _process_page(self, context, url: str, depth: int) -> PageResult:
        page = await context.new_page()

        # Per-page collectors populated by the Playwright event listeners below.
        console_errors: List[dict] = []
        page_errors: List[dict] = []
        failed_requests: List[dict] = []
        network_requests: List[str] = []

        def _on_console(msg) -> None:
            try:
                if msg.type in ("error", "warning"):
                    console_errors.append({"type": msg.type, "text": msg.text})
            except Exception:
                pass

        def _on_page_error(exc) -> None:
            page_errors.append({"message": str(exc)})

        def _on_request_failed(request) -> None:
            try:
                failure = request.failure or ""
            except Exception:
                failure = ""
            failed_requests.append({"url": request.url, "failure": failure})

        def _on_request(request) -> None:
            # Record every sub-resource URL so the privacy module can detect
            # trackers that fire before any consent interaction. Capped for memory.
            if len(network_requests) < 400:
                try:
                    network_requests.append(request.url)
                except Exception:
                    pass

        page.on("console", _on_console)
        page.on("pageerror", _on_page_error)
        page.on("requestfailed", _on_request_failed)
        page.on("request", _on_request)

        status, headers, final_url, html, load_error = 0, {}, url, "", ""
        cookies: List[dict] = []
        small_targets: List[dict] = []
        started = time.monotonic()
        try:
            # Start from a clean slate so any cookie/tracker we observe is
            # unambiguously dropped *before* the user could give consent.
            try:
                await context.clear_cookies()
            except PlaywrightError:
                pass

            try:
                response = await page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=self.config.page_timeout_ms,
                )
            except PlaywrightTimeoutError:
                response = None
                load_error = "Navigation timed out"

            # Give late-firing scripts / XHR a brief window to surface errors.
            try:
                await page.wait_for_load_state("networkidle", timeout=self.config.settle_ms)
            except PlaywrightTimeoutError:
                pass  # networkidle is best-effort only.

            if response is not None:
                status = response.status
                headers = {k.lower(): v for k, v in response.headers.items()}
            final_url = page.url or url
            try:
                html = await page.content()
            except PlaywrightError:
                html = ""

            # Privacy + accessibility signals captured from the live page.
            try:
                cookies = await context.cookies()
            except PlaywrightError:
                cookies = []
            if "accessibility" in self.config.modules:
                try:
                    small_targets = await page.evaluate(_TARGET_SIZE_JS)
                except Exception:
                    small_targets = []
        except PlaywrightError as exc:
            # DNS failure, connection refused, SSL error, ERR_TOO_MANY_REDIRECTS...
            load_error = _clean_pw_error(str(exc))
        finally:
            load_ms = int((time.monotonic() - started) * 1000)
            try:
                await page.close()
            except PlaywrightError:
                pass

        norm_requested = normalize_url(url)
        norm_final = normalize_url(final_url)
        self.page_status[norm_requested] = status
        self.page_status[norm_final] = status

        result = PageResult(
            url=url, final_url=final_url, status=status, depth=depth,
            load_time_ms=load_ms, error=load_error,
            console_errors=console_errors, page_errors=page_errors,
            failed_requests=failed_requests,
        )

        # --- Hard load failure: report as a dead link and stop here. --------
        if not html and (status == 0 or load_error):
            self._add_issue(Issue(
                SEVERITY_CRITICAL, CATEGORY_DEAD_LINKS, "unreachable",
                f"Page could not be loaded: {load_error or 'no response'}",
                url,
                _redirect_hint(load_error),
            ))
            result.ok = False
            return result

        # --- HTTP error status on a rendered page. --------------------------
        if status >= 400:
            severity = SEVERITY_CRITICAL if status >= 500 else SEVERITY_WARNING
            self._add_issue(Issue(
                severity, CATEGORY_DEAD_LINKS, "broken-page",
                f"Page returned HTTP {status}.",
                final_url,
                f"Requested: {url}",
            ))

        # --- Parse, extract links, run analyzers. ---------------------------
        soup = _make_soup(html)
        result.title = _extract_title(soup)

        internal_links, all_links = self._extract_links(soup, final_url)
        result.internal_links = internal_links
        for target in all_links:
            self.discovered_links[target].add(final_url)

        if status < 400:
            ctx = AnalyzerContext(
                url=url, final_url=final_url, status=status, headers=headers,
                html=html, soup=soup, base_domain=self.base_root,
                console_errors=console_errors, page_errors=page_errors,
                failed_requests=failed_requests,
                cookies=cookies, network_requests=network_requests,
                small_targets=small_targets,
            )
            for analyzer in self.analyzers:
                try:
                    for issue in analyzer.analyze(ctx):
                        self._add_issue(issue)
                except Exception as exc:  # never let one analyzer kill the crawl
                    self._add_issue(Issue(
                        SEVERITY_WARNING, "Bugs", "analyzer-error",
                        f"Analyzer {type(analyzer).__name__} raised an error.",
                        final_url, str(exc),
                    ))

        result.ok = status < 400 and bool(html)
        return result

    # -- link extraction ----------------------------------------------------
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> Tuple[List[str], List[str]]:
        """Return ``(internal_link_urls, all_normalized_targets)``."""
        internal: List[str] = []
        all_targets: List[str] = []
        seen: Set[str] = set()
        for anchor in soup.find_all("a", href=True):
            href = (anchor["href"] or "").strip()
            if not href or href.lower().startswith(_SKIP_PREFIXES):
                continue
            absolute = urljoin(base_url, href)
            parts = urlparse(absolute)
            if parts.scheme not in ("http", "https"):
                continue
            norm = normalize_url(absolute)
            if norm in seen:
                continue
            seen.add(norm)
            all_targets.append(norm)
            if self._is_internal(absolute):
                internal.append(absolute)
        return internal, all_targets

    def _is_internal(self, url: str) -> bool:
        host = registrable_host(urlparse(url).netloc)
        if not host:
            return True  # already-resolved relative link
        return host == self.base_root or host.endswith("." + self.base_root)

    # -- asynchronous link verification ------------------------------------
    async def _check_links(self) -> None:
        """Verify discovered links that were not already rendered successfully."""
        targets: List[str] = []
        for target in self.discovered_links:
            status = self.page_status.get(target)
            # Already crawled: its status (good or bad) is known and reported.
            if status is not None:
                continue
            targets.append(target)
        targets = targets[: self.config.max_links_check]

        self.links_total = len(targets)
        self.links_checked = 0
        self._emit_progress(phase="checking_links")
        if not targets:
            return

        timeout = aiohttp.ClientTimeout(total=self.config.link_timeout_s)
        # ``ssl=False`` lets us probe hosts with invalid/self-signed certs so a
        # bad certificate does not masquerade as a dead link.
        connector = aiohttp.TCPConnector(limit=self.config.link_concurrency, ssl=False)
        semaphore = asyncio.Semaphore(self.config.link_concurrency)

        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={"User-Agent": self.config.user_agent},
        ) as session:
            tasks = [
                asyncio.ensure_future(self._check_one(session, semaphore, target))
                for target in targets
            ]
            try:
                for future in asyncio.as_completed(tasks):
                    res = await future
                    self.links_checked += 1
                    self._handle_link_result(res)
                    self._emit_progress(phase="checking_links")
                    if self.should_stop():
                        break
            finally:
                for task in tasks:
                    if not task.done():
                        task.cancel()

    async def _check_one(self, session, semaphore, url: str) -> LinkCheckResult:
        """HEAD (then GET fallback) a single URL, classifying the result."""
        async with semaphore:
            # Try a cheap HEAD first; many servers reject it, so fall back to GET.
            for method in ("head", "get"):
                try:
                    request = getattr(session, method)
                    async with request(
                        url,
                        allow_redirects=True,
                        max_redirects=self.config.max_redirects,
                    ) as resp:
                        chain = [str(h.url) for h in resp.history]
                        # A repeated URL in the redirect chain is a loop.
                        if len(chain) != len(set(chain)):
                            return LinkCheckResult(url, -1, is_loop=True, redirect_chain=chain)
                        if method == "head" and resp.status >= 400:
                            break  # retry with GET before trusting a 4xx/5xx.
                        return LinkCheckResult(url, resp.status, redirect_chain=chain)
                except aiohttp.TooManyRedirects:
                    return LinkCheckResult(url, -1, is_loop=True)
                except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                    if method == "get":
                        return LinkCheckResult(url, 0, error=_clean_pw_error(str(exc)) or "connection failed")
                    # otherwise fall through and retry with GET
                except Exception as exc:  # noqa: BLE001 - defensive catch-all
                    if method == "get":
                        return LinkCheckResult(url, 0, error=str(exc))
        return LinkCheckResult(url, 0, error="connection failed")

    def _handle_link_result(self, res: LinkCheckResult) -> None:
        sources = self.discovered_links.get(res.url, set())
        source = next(iter(sources), res.url)
        ref = f"referenced from {len(sources)} page(s)" if sources else ""
        internal = self._is_internal(res.url)
        scope = "internal" if internal else "external"

        if res.is_loop:
            self._add_issue(Issue(
                SEVERITY_CRITICAL, CATEGORY_DEAD_LINKS, "redirect-loop",
                f"Redirect loop detected on {scope} link: {res.url}",
                source,
                " -> ".join(res.redirect_chain) if res.redirect_chain else ref,
            ))
        elif res.status == 0:
            self._add_issue(Issue(
                SEVERITY_WARNING, CATEGORY_DEAD_LINKS, "unreachable-link",
                f"Unreachable {scope} link: {res.url}",
                source,
                f"{res.error}; {ref}".strip("; "),
            ))
        elif res.status == 404:
            self._add_issue(Issue(
                SEVERITY_WARNING, CATEGORY_DEAD_LINKS, "broken-link",
                f"Broken {scope} link (HTTP 404): {res.url}",
                source, ref,
            ))
        elif res.status >= 400:
            severity = SEVERITY_CRITICAL if (res.status >= 500 and internal) else SEVERITY_WARNING
            self._add_issue(Issue(
                severity, CATEGORY_DEAD_LINKS, "broken-link",
                f"Broken {scope} link (HTTP {res.status}): {res.url}",
                source, ref,
            ))
        # 2xx / 3xx-resolved-to-2xx links are healthy and produce no issue.

    # -- callbacks / bookkeeping -------------------------------------------
    def _add_issue(self, issue: Issue) -> None:
        """De-duplicate identical findings before forwarding to the caller."""
        key = issue.dedup_key()
        if key in self._issue_keys:
            return
        self._issue_keys.add(key)
        # Attach the legal / financial mapping to every finding centrally.
        annotate_legal(issue)
        if self.on_issue:
            self.on_issue(issue)

    def _emit_progress(self, phase: Optional[str] = None, current_url: Optional[str] = None) -> None:
        if phase:
            self.phase = phase
        if current_url is not None:
            self.current_url = current_url
        if not self.on_progress:
            return
        self.on_progress({
            "phase": self.phase,
            "pages_scanned": self.pages_scanned,
            "pages_discovered": self.pages_scanned + self.queue_size,
            "queue_size": self.queue_size,
            "max_pages": self.config.max_pages,
            "links_checked": self.links_checked,
            "links_total": self.links_total,
            "current_url": self.current_url,
            "issues_found": len(self._issue_keys),
        })


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------
def _ensure_scheme(url: str) -> str:
    """Prepend ``https://`` when the user omits the scheme."""
    url = (url or "").strip()
    if not urlparse(url).scheme:
        return "https://" + url
    return url


def _make_soup(html: str) -> BeautifulSoup:
    """Parse HTML, preferring the fast lxml parser when it is installed."""
    try:
        return BeautifulSoup(html, "lxml")
    except Exception:
        return BeautifulSoup(html, "html.parser")


def _extract_title(soup: BeautifulSoup) -> str:
    if soup.title and soup.title.string:
        return soup.title.string.strip()
    return ""


def _clean_pw_error(message: str) -> str:
    """Reduce a verbose Playwright/aiohttp error to its first meaningful line."""
    message = (message or "").strip()
    first = message.splitlines()[0] if message else ""
    return first[:200]


def _redirect_hint(error: str) -> str:
    low = (error or "").lower()
    if "too_many_redirects" in low or "redirect" in low:
        return "Likely a redirect loop."
    if "name_not_resolved" in low or "dns" in low:
        return "DNS resolution failed - the host may not exist."
    if "connection_refused" in low or "refused" in low:
        return "The server refused the connection."
    if "ssl" in low or "cert" in low:
        return "TLS/SSL handshake problem."
    return error or ""
