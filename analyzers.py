"""
analyzers.py
============
Modular audit checks for the Site Auditor.

Each analyzer is a small, self-contained class exposing an ``analyze(context)``
method that receives an :class:`AnalyzerContext` for a single rendered page and
returns a list of :class:`Issue` objects.

Analyzers are instantiated **once per scan** (not per page) so that cross-page
checks - such as duplicate ``<title>`` / meta-description detection - can keep
state across the whole crawl.

Every finding is mapped - via :data:`LEGAL_MAP` / :func:`annotate_legal` - to the
specific regulation(s) it implicates and an indicative financial / operational
repercussion, and :func:`compute_risk` rolls the findings up into a single
"Legal & Compliance Risk Index".

Implemented modules
-------------------
* :class:`SecurityAnalyzer`      - security headers, mixed content, secret /
  staging-URL leaks (FTC Act § 5, breach-notification exposure).
* :class:`AccessibilityAnalyzer` - WCAG 2.2 DOM checks incl. target-size and
  ARIA landmarks (ADA Title III, Section 508, EAA).
* :class:`PrivacyAnalyzer`       - pre-consent trackers / cookies, cookie-banner
  dark patterns, missing policy links, insecure PII forms (GDPR, ePrivacy,
  CCPA/CPRA, VCDPA, TDPSA, CIPA).
* :class:`ContentAnalyzer`       - readability plus cross-page contradiction
  detection and an LLM-ready hook (state UDAP / false-advertising risk).
* :class:`SeoAnalyzer`           - technical SEO: canonical, viewport, robots
  indexability, Open-Graph / Twitter cards and structured data.
* :class:`BugAnalyzer`           - JavaScript console errors, uncaught
  exceptions and failed network requests captured by Playwright.

The "Dead Links" category is produced by :mod:`crawler` (it owns the async HTTP
client), but reuses the same :class:`Issue` data structure defined here.
"""

from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Severity / category constants
# ---------------------------------------------------------------------------
SEVERITY_CRITICAL = "Critical"
SEVERITY_WARNING = "Warning"
SEVERITY_INFO = "Info"

CATEGORY_SECURITY = "Security"
CATEGORY_ACCESSIBILITY = "Accessibility"
CATEGORY_PRIVACY = "Privacy"
CATEGORY_CONTENT = "Content"
CATEGORY_SEO = "SEO"
CATEGORY_BUGS = "Bugs"
CATEGORY_DEAD_LINKS = "Dead Links"

# Ordering helper so the UI can sort by importance.
SEVERITY_ORDER = {SEVERITY_CRITICAL: 0, SEVERITY_WARNING: 1, SEVERITY_INFO: 2}

# ---------------------------------------------------------------------------
# Shared data structures
# ---------------------------------------------------------------------------
@dataclass
class Issue:
    """A single audit finding.

    Attributes
    ----------
    severity : str   - one of ``Critical`` / ``Warning`` / ``Info``.
    category : str   - high level grouping (Security, Accessibility, ...).
    type     : str   - short machine-ish identifier for the rule.
    message  : str   - human readable summary (the *Technical Error*).
    url      : str   - the page (or resource) the issue was found on.
    details  : str   - optional extra context (snippet, header value, ...).
    law      : str   - the specific law / standard implicated (filled in by
                       :func:`annotate_legal`).
    penalty  : str   - indicative financial / operational repercussion.
    """

    severity: str
    category: str
    type: str
    message: str
    url: str
    details: str = ""
    law: str = ""
    penalty: str = ""

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)

    def dedup_key(self) -> Tuple[str, str, str, str, str]:
        """Key used to suppress exact-duplicate findings within a scan."""
        return (self.severity, self.category, self.type, self.url, self.message)


@dataclass
class AnalyzerContext:
    """All per-page information handed to the analyzers."""

    url: str                       # URL we requested
    final_url: str                 # URL after any redirects
    status: int                    # HTTP status code of the main document
    headers: Dict[str, str]        # response headers (lower-cased keys)
    html: str                      # fully rendered HTML
    soup: BeautifulSoup            # parsed DOM
    base_domain: str               # registrable host of the crawl root
    console_errors: List[dict] = field(default_factory=list)
    page_errors: List[dict] = field(default_factory=list)
    failed_requests: List[dict] = field(default_factory=list)
    # Enriched signals captured live by the Playwright crawler:
    cookies: List[dict] = field(default_factory=list)          # cookies set on load
    network_requests: List[str] = field(default_factory=list)  # all sub-resource URLs
    small_targets: List[dict] = field(default_factory=list)    # interactive els < 24x24px

    @property
    def is_https(self) -> bool:
        return urlparse(self.final_url).scheme == "https"

    def third_party_hosts(self) -> List[str]:
        """Distinct request hosts that are not part of the audited domain."""
        hosts: List[str] = []
        seen: set = set()
        for raw in self.network_requests:
            host = urlparse(raw).netloc.lower().split(":")[0]
            if not host or host in seen:
                continue
            seen.add(host)
            reg = host[4:] if host.startswith("www.") else host
            if reg == self.base_domain or reg.endswith("." + self.base_domain):
                continue
            hosts.append(host)
        return hosts


# ---------------------------------------------------------------------------
# Security analyzer
# ---------------------------------------------------------------------------
class SecurityAnalyzer:
    """Checks security headers, mixed content and leaked secrets.

    Header findings are reported only once per scan (keyed on the header name)
    to avoid flooding the report when every page shares the same configuration.
    """

    # Headers we expect to see, with the severity used when they are absent and
    # a short explanation shown in the report.
    SECURITY_HEADERS = {
        "content-security-policy": (
            SEVERITY_WARNING,
            "Mitigates XSS and data-injection attacks by restricting resource origins.",
        ),
        "x-frame-options": (
            SEVERITY_WARNING,
            "Protects against click-jacking by controlling whether the page may be framed.",
        ),
        "strict-transport-security": (
            SEVERITY_WARNING,
            "Forces browsers to use HTTPS for future requests (HSTS).",
        ),
        "x-content-type-options": (
            SEVERITY_INFO,
            "Should be 'nosniff' to stop MIME-type sniffing.",
        ),
        "referrer-policy": (
            SEVERITY_INFO,
            "Controls how much referrer information is shared with other sites.",
        ),
        "permissions-policy": (
            SEVERITY_INFO,
            "Restricts access to powerful browser features (camera, geolocation, ...).",
        ),
    }

    # Precompiled high-confidence secret patterns. Tuple = (regex, label, severity).
    SECRET_PATTERNS = [
        (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS Access Key ID", SEVERITY_CRITICAL),
        (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "Google API Key", SEVERITY_CRITICAL),
        (re.compile(r"\bya29\.[0-9A-Za-z_\-]+"), "Google OAuth Access Token", SEVERITY_CRITICAL),
        (re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}"), "Slack Token", SEVERITY_CRITICAL),
        (re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}"), "GitHub Token", SEVERITY_CRITICAL),
        (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
         "Private Key Block", SEVERITY_CRITICAL),
        (re.compile(r"\bsk_live_[0-9A-Za-z]{16,}"), "Stripe Live Secret Key", SEVERITY_CRITICAL),
    ]

    # Lower-confidence assignment style leaks (scanned in inline scripts only).
    GENERIC_SECRET_RE = re.compile(
        r"""(?ix)
        (api[_-]?key|secret(?:_key)?|access[_-]?token|auth[_-]?token|
         passwd|password|client[_-]?secret)
        \s*[:=]\s*
        ['"]([^'"]{8,})['"]
        """
    )

    # Environment-variable style leaks. Case-sensitive on purpose: real env vars
    # are conventionally UPPER_CASE, which avoids flagging ordinary lower-case
    # JavaScript variables such as ``api_key``.
    ENV_LEAK_RE = re.compile(
        r"\b(DB_PASSWORD|DATABASE_URL|AWS_SECRET_ACCESS_KEY|SECRET_KEY|"
        r"PRIVATE_KEY|API_KEY|MYSQL_ROOT_PASSWORD|REDIS_PASSWORD)\b\s*[:=]"
    )

    # Sensitive / admin paths that should usually not be publicly linked.
    SENSITIVE_PATHS = [
        ("wp-login.php", "WordPress login page", SEVERITY_WARNING),
        ("/wp-admin", "WordPress admin area", SEVERITY_WARNING),
        ("/.env", "Environment file", SEVERITY_CRITICAL),
        ("/.git", "Exposed Git directory", SEVERITY_CRITICAL),
        ("phpmyadmin", "phpMyAdmin console", SEVERITY_WARNING),
        ("/.htaccess", "Apache config file", SEVERITY_WARNING),
        ("/server-status", "Apache server-status", SEVERITY_WARNING),
        ("/config.php", "Configuration file", SEVERITY_WARNING),
        ("/backup", "Backup path", SEVERITY_INFO),
    ]

    # Tags whose external resources count as *active* mixed content (more severe).
    ACTIVE_MIXED_TAGS = {"script", "iframe", "object", "embed"}

    # Internal / non-production hostnames that should never ship to production.
    STAGING_HOST_RE = re.compile(
        r"https?://[a-z0-9.\-]*?(?:staging|stage|dev|test|qa|uat|preprod|"
        r"localhost|127\.0\.0\.1|internal|sandbox)[a-z0-9.\-]*",
        re.IGNORECASE,
    )

    def __init__(self) -> None:
        # Remember which header findings we have already emitted so each missing
        # header is only reported a single time for the whole site.
        self._reported_headers: set = set()
        self._reported_secrets: set = set()
        self._reported_staging: set = set()

    def analyze(self, ctx: AnalyzerContext) -> List[Issue]:
        issues: List[Issue] = []
        issues.extend(self._check_headers(ctx))
        issues.extend(self._check_mixed_content(ctx))
        issues.extend(self._check_secrets(ctx))
        issues.extend(self._check_sensitive_paths(ctx))
        issues.extend(self._check_staging_urls(ctx))
        return issues

    # -- headers ------------------------------------------------------------
    def _check_headers(self, ctx: AnalyzerContext) -> List[Issue]:
        issues: List[Issue] = []
        # Header checks only make sense for a successfully served document.
        if not ctx.headers or ctx.status >= 400:
            return issues

        for header, (severity, explanation) in self.SECURITY_HEADERS.items():
            # HSTS is only relevant on HTTPS responses.
            if header == "strict-transport-security" and not ctx.is_https:
                continue
            if header in ctx.headers:
                # x-content-type-options should specifically be 'nosniff'.
                if header == "x-content-type-options" and \
                        ctx.headers[header].strip().lower() != "nosniff":
                    key = (header, "value")
                    if key not in self._reported_headers:
                        self._reported_headers.add(key)
                        issues.append(Issue(
                            SEVERITY_INFO, CATEGORY_SECURITY, "weak-security-header",
                            "X-Content-Type-Options is not set to 'nosniff'.",
                            ctx.final_url,
                            f"Current value: {ctx.headers[header]!r}",
                        ))
                continue

            key = (header, "missing")
            if key in self._reported_headers:
                continue
            self._reported_headers.add(key)
            issues.append(Issue(
                severity, CATEGORY_SECURITY, "missing-security-header",
                f"Missing security header: {header}",
                ctx.final_url,
                explanation,
            ))
        return issues

    # -- mixed content ------------------------------------------------------
    def _check_mixed_content(self, ctx: AnalyzerContext) -> List[Issue]:
        """Flag http:// sub-resources loaded by an https:// page."""
        issues: List[Issue] = []
        if not ctx.is_https:
            return issues

        seen: set = set()
        # (tag, attribute) pairs that can reference an external resource.
        attr_map = [
            ("img", "src"), ("script", "src"), ("link", "href"),
            ("iframe", "src"), ("audio", "src"), ("video", "src"),
            ("source", "src"), ("object", "data"), ("embed", "src"),
            ("form", "action"),
        ]
        for tag_name, attr in attr_map:
            for tag in ctx.soup.find_all(tag_name):
                value = (tag.get(attr) or "").strip()
                if not value.lower().startswith("http://"):
                    continue
                if value in seen:
                    continue
                seen.add(value)
                active = tag_name in self.ACTIVE_MIXED_TAGS or (
                    tag_name == "link" and "stylesheet" in (tag.get("rel") or [])
                )
                severity = SEVERITY_CRITICAL if active else SEVERITY_WARNING
                issues.append(Issue(
                    severity, CATEGORY_SECURITY, "mixed-content",
                    f"Insecure (HTTP) resource loaded on an HTTPS page via <{tag_name}>.",
                    ctx.final_url,
                    value,
                ))
        return issues

    # -- secret / credential leaks -----------------------------------------
    def _check_secrets(self, ctx: AnalyzerContext) -> List[Issue]:
        issues: List[Issue] = []

        # High-confidence patterns scanned across the whole document.
        for pattern, label, severity in self.SECRET_PATTERNS:
            for match in pattern.findall(ctx.html):
                snippet = match if isinstance(match, str) else match[0]
                key = (label, snippet[:12])
                if key in self._reported_secrets:
                    continue
                self._reported_secrets.add(key)
                issues.append(Issue(
                    severity, CATEGORY_SECURITY, "exposed-secret",
                    f"Possible exposed {label} found in page source.",
                    ctx.final_url,
                    _redact(snippet),
                ))

        # Lower-confidence assignment leaks scanned inside inline scripts only.
        for script in ctx.soup.find_all("script"):
            text = script.string or ""
            for m in self.GENERIC_SECRET_RE.finditer(text):
                name, value = m.group(1), m.group(2)
                if _looks_like_placeholder(value):
                    continue
                key = ("generic", name.lower(), value[:12])
                if key in self._reported_secrets:
                    continue
                self._reported_secrets.add(key)
                issues.append(Issue(
                    SEVERITY_WARNING, CATEGORY_SECURITY, "exposed-secret",
                    f"Hard-coded credential '{name}' assigned in inline JavaScript.",
                    ctx.final_url,
                    f"{name} = {_redact(value)}",
                ))

        # Environment variable leaks anywhere in the source.
        if self.ENV_LEAK_RE.search(ctx.html):
            names = ", ".join(sorted({m.group(1) for m in self.ENV_LEAK_RE.finditer(ctx.html)}))
            key = ("env", names)
            if key not in self._reported_secrets:
                self._reported_secrets.add(key)
                issues.append(Issue(
                    SEVERITY_CRITICAL, CATEGORY_SECURITY, "exposed-env-var",
                    "Environment-variable style secret reference exposed in page source.",
                    ctx.final_url,
                    names,
                ))
        return issues

    # -- sensitive / admin paths -------------------------------------------
    def _check_sensitive_paths(self, ctx: AnalyzerContext) -> List[Issue]:
        issues: List[Issue] = []
        seen: set = set()
        for a in ctx.soup.find_all(["a", "link", "form"]):
            href = (a.get("href") or a.get("action") or "").lower()
            if not href:
                continue
            for needle, label, severity in self.SENSITIVE_PATHS:
                if needle in href and needle not in seen:
                    seen.add(needle)
                    issues.append(Issue(
                        severity, CATEGORY_SECURITY, "sensitive-path",
                        f"Reference to a potentially sensitive path ({label}).",
                        ctx.final_url,
                        href,
                    ))
        return issues

    # -- leaked internal / staging URLs ------------------------------------
    def _check_staging_urls(self, ctx: AnalyzerContext) -> List[Issue]:
        """Flag references to non-production (staging/dev/internal) hosts."""
        issues: List[Issue] = []
        for match in self.STAGING_HOST_RE.findall(ctx.html):
            host = urlparse(match).netloc.lower()
            # Ignore matches that are actually the site we are auditing.
            reg = host[4:] if host.startswith("www.") else host
            if reg == ctx.base_domain or reg.endswith("." + ctx.base_domain):
                continue
            if host in self._reported_staging:
                continue
            self._reported_staging.add(host)
            issues.append(Issue(
                SEVERITY_WARNING, CATEGORY_SECURITY, "staging-url",
                "Reference to an internal / non-production host exposed in source.",
                ctx.final_url,
                match[:200],
            ))
        return issues


# ---------------------------------------------------------------------------
# Accessibility analyzer
# ---------------------------------------------------------------------------
class AccessibilityAnalyzer:
    """WCAG-oriented DOM checks."""

    # Link text considered non-descriptive for screen-reader users.
    VAGUE_LINK_TEXT = {
        "click here", "here", "read more", "more", "learn more",
        "this", "link", "details", "continue", "go", "click",
    }

    def analyze(self, ctx: AnalyzerContext) -> List[Issue]:
        # Only audit real HTML documents.
        if ctx.status >= 400:
            return []
        issues: List[Issue] = []
        issues.extend(self._check_lang(ctx))
        issues.extend(self._check_title(ctx))
        issues.extend(self._check_images(ctx))
        issues.extend(self._check_headings(ctx))
        issues.extend(self._check_link_text(ctx))
        issues.extend(self._check_form_labels(ctx))
        issues.extend(self._check_landmarks(ctx))       # ARIA landmarks
        issues.extend(self._check_target_size(ctx))     # WCAG 2.2 SC 2.5.8
        return issues

    def _check_lang(self, ctx: AnalyzerContext) -> List[Issue]:
        html_tag = ctx.soup.find("html")
        if html_tag is None or not (html_tag.get("lang") or "").strip():
            return [Issue(
                SEVERITY_WARNING, CATEGORY_ACCESSIBILITY, "missing-lang",
                "The <html> element is missing a 'lang' attribute.",
                ctx.final_url,
                "Screen readers rely on 'lang' to choose the correct pronunciation.",
            )]
        return []

    def _check_title(self, ctx: AnalyzerContext) -> List[Issue]:
        title = ctx.soup.title.string if ctx.soup.title else None
        if not (title or "").strip():
            return [Issue(
                SEVERITY_WARNING, CATEGORY_ACCESSIBILITY, "missing-title",
                "The page has no <title> element (or it is empty).",
                ctx.final_url,
                "A descriptive title is required for orientation and SEO.",
            )]
        return []

    def _check_images(self, ctx: AnalyzerContext) -> List[Issue]:
        issues: List[Issue] = []
        missing = 0
        examples: List[str] = []
        for img in ctx.soup.find_all("img"):
            # Decorative images may legitimately use alt="" or be hidden.
            if img.get("role") == "presentation" or img.get("aria-hidden") == "true":
                continue
            if img.get("aria-label") or img.get("aria-labelledby"):
                continue
            if img.get("alt") is None:  # attribute completely absent
                missing += 1
                if len(examples) < 5:
                    examples.append((img.get("src") or "<inline>")[:120])
        if missing:
            issues.append(Issue(
                SEVERITY_WARNING, CATEGORY_ACCESSIBILITY, "img-missing-alt",
                f"{missing} image(s) are missing an 'alt' attribute.",
                ctx.final_url,
                "; ".join(examples),
            ))
        return issues

    def _check_headings(self, ctx: AnalyzerContext) -> List[Issue]:
        issues: List[Issue] = []
        headings = ctx.soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"])
        levels = [int(h.name[1]) for h in headings]

        h1_count = levels.count(1)
        if h1_count == 0:
            issues.append(Issue(
                SEVERITY_WARNING, CATEGORY_ACCESSIBILITY, "missing-h1",
                "The page does not contain an <h1> heading.",
                ctx.final_url,
                "Each page should have exactly one top-level <h1>.",
            ))
        elif h1_count > 1:
            issues.append(Issue(
                SEVERITY_INFO, CATEGORY_ACCESSIBILITY, "multiple-h1",
                f"The page contains {h1_count} <h1> headings.",
                ctx.final_url,
                "Multiple <h1> elements can confuse assistive technology.",
            ))

        # Detect skipped levels (e.g. <h2> directly followed by <h4>).
        previous = 0
        for level in levels:
            if previous and level > previous + 1:
                issues.append(Issue(
                    SEVERITY_WARNING, CATEGORY_ACCESSIBILITY, "skipped-heading-level",
                    f"Heading levels jump from <h{previous}> to <h{level}>.",
                    ctx.final_url,
                    "Do not skip heading levels - it breaks the document outline.",
                ))
                break  # one report per page is enough
            previous = level
        return issues

    def _check_link_text(self, ctx: AnalyzerContext) -> List[Issue]:
        issues: List[Issue] = []
        vague = 0
        empty = 0
        examples: List[str] = []
        for a in ctx.soup.find_all("a"):
            if not (a.get("href") or "").strip():
                continue
            text = a.get_text(strip=True).lower()
            # An image with alt text or an aria-label provides an accessible name.
            has_alt_img = any((img.get("alt") or "").strip() for img in a.find_all("img"))
            accessible_name = text or a.get("aria-label") or a.get("title") or has_alt_img
            if not accessible_name:
                empty += 1
                continue
            if text in self.VAGUE_LINK_TEXT:
                vague += 1
                if len(examples) < 5:
                    examples.append(text)
        if vague:
            issues.append(Issue(
                SEVERITY_WARNING, CATEGORY_ACCESSIBILITY, "vague-link-text",
                f"{vague} link(s) use non-descriptive text (e.g. 'click here').",
                ctx.final_url,
                "; ".join(sorted(set(examples))),
            ))
        if empty:
            issues.append(Issue(
                SEVERITY_WARNING, CATEGORY_ACCESSIBILITY, "empty-link",
                f"{empty} link(s) have no discernible accessible text.",
                ctx.final_url,
                "Add visible text, an aria-label, or alt text on a child image.",
            ))
        return issues

    def _check_form_labels(self, ctx: AnalyzerContext) -> List[Issue]:
        issues: List[Issue] = []
        # Collect the ids referenced by <label for="...">.
        label_targets = {
            (lbl.get("for") or "").strip()
            for lbl in ctx.soup.find_all("label") if lbl.get("for")
        }
        skip_types = {"hidden", "submit", "button", "reset", "image"}
        unlabeled = 0
        for field_el in ctx.soup.find_all(["input", "select", "textarea"]):
            if field_el.name == "input" and (field_el.get("type") or "text").lower() in skip_types:
                continue
            # Any of these give the control an accessible name.
            if field_el.get("aria-label") or field_el.get("aria-labelledby") \
                    or field_el.get("title"):
                continue
            field_id = (field_el.get("id") or "").strip()
            if field_id and field_id in label_targets:
                continue
            # Wrapped directly inside a <label> element?
            if field_el.find_parent("label") is not None:
                continue
            unlabeled += 1
        if unlabeled:
            issues.append(Issue(
                SEVERITY_WARNING, CATEGORY_ACCESSIBILITY, "form-missing-label",
                f"{unlabeled} form control(s) have no associated label.",
                ctx.final_url,
                "Associate a <label for> or add an aria-label to each control.",
            ))
        return issues

    def _check_landmarks(self, ctx: AnalyzerContext) -> List[Issue]:
        """Flag missing primary ARIA landmarks (WCAG 1.3.1 / ARIA practices)."""
        issues: List[Issue] = []

        def has(tag_names, roles) -> bool:
            if ctx.soup.find(tag_names) is not None:
                return True
            for role in roles:
                if ctx.soup.find(attrs={"role": role}) is not None:
                    return True
            return False

        # The main landmark is the most important for keyboard/AT users.
        if not has(["main"], ["main"]):
            issues.append(Issue(
                SEVERITY_WARNING, CATEGORY_ACCESSIBILITY, "missing-landmark",
                "No main landmark (<main> or role=\"main\") was found.",
                ctx.final_url,
                "Screen-reader users rely on landmarks to skip to primary content.",
            ))
        # Navigation landmark (informational).
        if not has(["nav"], ["navigation"]):
            issues.append(Issue(
                SEVERITY_INFO, CATEGORY_ACCESSIBILITY, "missing-landmark",
                "No navigation landmark (<nav> or role=\"navigation\") was found.",
                ctx.final_url,
                "Expose primary navigation as a landmark for assistive technology.",
            ))
        return issues

    def _check_target_size(self, ctx: AnalyzerContext) -> List[Issue]:
        """WCAG 2.2 SC 2.5.8 - interactive targets must be at least 24x24 CSS px.

        The measurements come from the live Playwright page (``ctx.small_targets``)
        because element dimensions cannot be derived from static HTML.
        """
        if not ctx.small_targets:
            return []
        examples = []
        for t in ctx.small_targets[:5]:
            label = (t.get("label") or t.get("selector") or "element").strip()
            examples.append(f"{label} ({t.get('w')}x{t.get('h')}px)")
        return [Issue(
            SEVERITY_WARNING, CATEGORY_ACCESSIBILITY, "target-size",
            f"{len(ctx.small_targets)} interactive target(s) are smaller than "
            "24x24px (WCAG 2.2, SC 2.5.8).",
            ctx.final_url,
            "; ".join(examples),
        )]


# ---------------------------------------------------------------------------
# Content quality analyzer
# ---------------------------------------------------------------------------
class ContentAnalyzer:
    """Content-quality heuristics plus duplicate title / meta detection.

    Cross-page duplicate detection relies on the analyzer instance persisting
    for the duration of a scan; ``self._titles`` / ``self._descriptions`` map a
    normalised string to the first URL on which it was seen.
    """

    THIN_CONTENT_WORDS = 100      # below this a page is considered "thin".
    TITLE_MIN, TITLE_MAX = 10, 60
    DESC_MIN, DESC_MAX = 50, 160
    READABILITY_FLOOR = 30.0      # Flesch Reading Ease below this == "very hard".

    def __init__(self) -> None:
        self._titles: Dict[str, str] = {}
        self._descriptions: Dict[str, str] = {}
        # Cross-page contradiction state (policy logic checks).
        self._refund_windows: Dict[int, str] = {}    # days -> first URL seen
        self._plan_prices: Dict[str, Tuple[str, str]] = {}  # plan -> (price, URL)
        self._page_corpus: List[Tuple[str, str]] = []       # (url, text) for finalize()
        self._refund_reported: set = set()
        self._price_reported: set = set()

    def analyze(self, ctx: AnalyzerContext) -> List[Issue]:
        if ctx.status >= 400:
            return []
        issues: List[Issue] = []
        issues.extend(self._check_title(ctx))
        issues.extend(self._check_meta_description(ctx))
        issues.extend(self._check_thin_and_readability(ctx))
        issues.extend(self._check_contradictions(ctx))
        issues.extend(self._check_cross_page_logic(ctx))
        return issues

    # -- title --------------------------------------------------------------
    def _check_title(self, ctx: AnalyzerContext) -> List[Issue]:
        issues: List[Issue] = []
        raw = (ctx.soup.title.string if ctx.soup.title else "") or ""
        title = raw.strip()
        if not title:
            return issues  # missing-title is already reported by the a11y module
        length = len(title)
        if length < self.TITLE_MIN:
            issues.append(Issue(
                SEVERITY_INFO, CATEGORY_CONTENT, "short-title",
                f"Title is very short ({length} characters).",
                ctx.final_url, title,
            ))
        elif length > self.TITLE_MAX:
            issues.append(Issue(
                SEVERITY_INFO, CATEGORY_CONTENT, "long-title",
                f"Title is long ({length} characters) and may be truncated in search results.",
                ctx.final_url, title,
            ))

        key = title.lower()
        if key in self._titles and self._titles[key] != ctx.final_url:
            issues.append(Issue(
                SEVERITY_WARNING, CATEGORY_CONTENT, "duplicate-title",
                "Duplicate <title> shared with another page.",
                ctx.final_url,
                f"Same title as {self._titles[key]}",
            ))
        else:
            self._titles.setdefault(key, ctx.final_url)
        return issues

    # -- meta description ---------------------------------------------------
    def _check_meta_description(self, ctx: AnalyzerContext) -> List[Issue]:
        issues: List[Issue] = []
        tag = ctx.soup.find("meta", attrs={"name": "description"})
        desc = (tag.get("content") if tag else "") or ""
        desc = desc.strip()
        if not desc:
            issues.append(Issue(
                SEVERITY_INFO, CATEGORY_CONTENT, "missing-meta-description",
                "The page has no meta description.",
                ctx.final_url,
                "A concise meta description improves click-through from search results.",
            ))
            return issues

        length = len(desc)
        if length < self.DESC_MIN:
            issues.append(Issue(
                SEVERITY_INFO, CATEGORY_CONTENT, "short-meta-description",
                f"Meta description is short ({length} characters).",
                ctx.final_url, desc,
            ))
        elif length > self.DESC_MAX:
            issues.append(Issue(
                SEVERITY_INFO, CATEGORY_CONTENT, "long-meta-description",
                f"Meta description is long ({length} characters) and may be truncated.",
                ctx.final_url, desc,
            ))

        key = desc.lower()
        if key in self._descriptions and self._descriptions[key] != ctx.final_url:
            issues.append(Issue(
                SEVERITY_WARNING, CATEGORY_CONTENT, "duplicate-meta-description",
                "Duplicate meta description shared with another page.",
                ctx.final_url,
                f"Same description as {self._descriptions[key]}",
            ))
        else:
            self._descriptions.setdefault(key, ctx.final_url)
        return issues

    # -- thin content + readability ----------------------------------------
    def _check_thin_and_readability(self, ctx: AnalyzerContext) -> List[Issue]:
        issues: List[Issue] = []
        text = _visible_text(ctx.soup)
        words = re.findall(r"[A-Za-z']+", text)
        word_count = len(words)

        if word_count < self.THIN_CONTENT_WORDS:
            issues.append(Issue(
                SEVERITY_INFO, CATEGORY_CONTENT, "thin-content",
                f"Page has little textual content ({word_count} words).",
                ctx.final_url,
                "Thin pages may rank poorly and offer limited value to users.",
            ))
            return issues  # readability is meaningless on tiny samples.

        score = _flesch_reading_ease(text, words)
        if score is not None and score < self.READABILITY_FLOOR:
            issues.append(Issue(
                SEVERITY_INFO, CATEGORY_CONTENT, "low-readability",
                f"Content is hard to read (Flesch score {score:.0f}/100).",
                ctx.final_url,
                "Shorter sentences and simpler words improve readability.",
            ))
        return issues

    # -- contradiction / LLM hook ------------------------------------------
    def _check_contradictions(self, ctx: AnalyzerContext) -> List[Issue]:
        """Heuristic content-integrity checks plus an LLM-ready extension point.

        The cheap heuristics below run with no external dependencies. The
        :meth:`llm_review` hook shows exactly where a call to an LLM API would be
        wired in for deeper "contradicting information" analysis.
        """
        issues: List[Issue] = []
        text = _visible_text(ctx.soup)
        lower = text.lower()

        # 1. Placeholder / boilerplate text left in production.
        if "lorem ipsum" in lower:
            issues.append(Issue(
                SEVERITY_WARNING, CATEGORY_CONTENT, "placeholder-text",
                "Placeholder 'lorem ipsum' text found on the page.",
                ctx.final_url,
                "Replace boilerplate copy before publishing.",
            ))

        # 2. Title vs <h1> conflict - the on-page heading contradicts the title.
        title = (ctx.soup.title.string if ctx.soup.title else "") or ""
        h1 = ctx.soup.find("h1")
        h1_text = h1.get_text(strip=True) if h1 else ""
        if title.strip() and h1_text and not _tokens_overlap(title, h1_text):
            issues.append(Issue(
                SEVERITY_INFO, CATEGORY_CONTENT, "title-h1-mismatch",
                "The <title> and the main <h1> share no common keywords.",
                ctx.final_url,
                f"title={title.strip()!r} h1={h1_text!r}",
            ))

        # 3. Optional deep analysis via an external LLM (disabled by default).
        issues.extend(self.llm_review(ctx, text))
        return issues

    def llm_review(self, ctx: AnalyzerContext, text: str) -> List[Issue]:
        """Structural placeholder for LLM-powered contradiction detection.

        To enable, send ``text`` to your LLM provider and translate the model's
        findings into :class:`Issue` objects, e.g.::

            client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
            resp = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system",
                     "content": "List factual contradictions in the text as JSON."},
                    {"role": "user", "content": text[:8000]},
                ],
            )
            for finding in json.loads(resp.choices[0].message.content):
                issues.append(Issue(
                    SEVERITY_INFO, CATEGORY_CONTENT, "llm-contradiction",
                    finding["summary"], ctx.final_url, finding.get("detail", ""),
                ))

        Returning an empty list keeps the auditor fully offline and free to run.
        """
        return []

    # -- cross-page policy / pricing contradictions ------------------------
    def _check_cross_page_logic(self, ctx: AnalyzerContext) -> List[Issue]:
        """Detect contradictions *between* pages (refund windows, plan prices).

        Findings are emitted live: when the current page introduces a value that
        conflicts with one already recorded on a different page, an issue is
        raised immediately (each conflicting pair is reported only once).
        """
        issues: List[Issue] = []
        text = _visible_text(ctx.soup)
        # Keep a bounded corpus for the optional LLM finalize() pass.
        self._page_corpus.append((ctx.final_url, text[:4000]))
        if len(self._page_corpus) > 60:
            self._page_corpus.pop(0)

        # 1. Refund / return / money-back windows.
        for days in sorted(_extract_refund_windows(text)):
            for known_days, known_url in list(self._refund_windows.items()):
                if known_days == days or known_url == ctx.final_url:
                    continue
                pair = frozenset((known_days, days))
                if pair in self._refund_reported:
                    continue
                self._refund_reported.add(pair)
                issues.append(Issue(
                    SEVERITY_CRITICAL, CATEGORY_CONTENT, "refund-contradiction",
                    f"Conflicting refund/return windows site-wide: "
                    f"{known_days} days vs {days} days.",
                    ctx.final_url,
                    f"{known_days} days stated at {known_url}; {days} days stated here.",
                ))
            self._refund_windows.setdefault(days, ctx.final_url)

        # 2. Subscription plan pricing.
        for plan, price in _extract_plan_prices(text).items():
            prior = self._plan_prices.get(plan)
            if prior and prior[0] != price and prior[1] != ctx.final_url:
                pair = (plan, frozenset((prior[0], price)))
                if pair not in self._price_reported:
                    self._price_reported.add(pair)
                    issues.append(Issue(
                        SEVERITY_WARNING, CATEGORY_CONTENT, "price-contradiction",
                        f"Conflicting price for the '{plan.title()}' plan: "
                        f"${prior[0]} vs ${price}.",
                        ctx.final_url,
                        f"${prior[0]} at {prior[1]}; ${price} stated here.",
                    ))
            else:
                self._plan_prices.setdefault(plan, (price, ctx.final_url))
        return issues

    def finalize(self) -> List[Issue]:
        """Whole-corpus contradiction pass run once after the crawl completes."""
        return self.llm_corpus_review(self._page_corpus)

    def llm_corpus_review(self, corpus: List[Tuple[str, str]]) -> List[Issue]:
        """Structural placeholder for *cross-page* LLM contradiction detection.

        Unlike :meth:`llm_review` (single page), this receives the whole crawl
        corpus so the model can reason about contradictions that span documents
        - e.g. a 30-day refund promise on the homepage versus a 14-day window in
        the Terms of Service. Wire it up like so::

            client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
            joined = "\\n\\n".join(f"URL: {u}\\n{t}" for u, t in corpus)
            resp = client.chat.completions.create(
                model="gpt-4o-mini",
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content":
                        "Find factual/policy contradictions across these pages. "
                        "Return JSON: {contradictions:[{summary,detail,urls:[]}]}"},
                    {"role": "user", "content": joined[:60000]},
                ],
            )
            data = json.loads(resp.choices[0].message.content)
            return [Issue(SEVERITY_CRITICAL, CATEGORY_CONTENT, "llm-contradiction",
                          c["summary"], (c.get("urls") or [""])[0], c.get("detail", ""))
                    for c in data.get("contradictions", [])]

        Returning an empty list keeps the auditor fully offline by default.
        """
        return []


# ---------------------------------------------------------------------------
# Privacy / cookie / tracker analyzer
# ---------------------------------------------------------------------------
class PrivacyAnalyzer:
    """Cookie, tracker and consent compliance checks.

    Relies on live signals captured by the crawler: cookies present immediately
    after load, every sub-resource request URL, and the rendered DOM. Because the
    crawler clears cookies before each navigation and never clicks "Accept",
    anything observed here is effectively **pre-consent** - exactly the state
    regulators scrutinise under GDPR/ePrivacy and CIPA wiretapping theories.
    """

    # Request-host fragments that identify a third-party tracker -> vendor label.
    TRACKER_HOSTS = {
        "google-analytics.com": "Google Analytics",
        "analytics.google.com": "Google Analytics 4",
        "googletagmanager.com": "Google Tag Manager",
        "doubleclick.net": "Google DoubleClick",
        "googlesyndication.com": "Google Ads",
        "facebook.com/tr": "Meta (Facebook) Pixel",
        "connect.facebook.net": "Meta (Facebook) Pixel",
        "analytics.tiktok.com": "TikTok Pixel",
        "hotjar.com": "Hotjar",
        "clarity.ms": "Microsoft Clarity",
        "bat.bing.com": "Microsoft Bing Ads",
        "snap.licdn.com": "LinkedIn Insight Tag",
        "px.ads.linkedin.com": "LinkedIn Ads",
        "static.ads-twitter.com": "X/Twitter Pixel",
        "analytics.twitter.com": "X/Twitter Ads",
        "cdn.amplitude.com": "Amplitude",
        "api.mixpanel.com": "Mixpanel",
        "cdn.segment.com": "Segment",
        "fullstory.com": "FullStory",
        "ct.pinterest.com": "Pinterest Tag",
        "cdn.heapanalytics.com": "Heap Analytics",
    }

    # Cookie-name fragments commonly set by trackers -> vendor label.
    TRACKER_COOKIES = {
        "_ga": "Google Analytics", "_gid": "Google Analytics", "_gat": "Google Analytics",
        "_gcl_au": "Google Ads", "_fbp": "Meta Pixel", "_fbc": "Meta Pixel",
        "fr": "Meta", "_ttp": "TikTok", "ttwid": "TikTok",
        "_hjsession": "Hotjar", "_clck": "Microsoft Clarity", "_clsk": "Microsoft Clarity",
        "muc_ads": "X/Twitter", "personalization_id": "X/Twitter",
        "li_sugr": "LinkedIn", "bcookie": "LinkedIn", "_pin_unauth": "Pinterest",
        "amplitude_id": "Amplitude", "mp_": "Mixpanel", "ajs_": "Segment",
    }

    ACCEPT_RE = re.compile(r"\b(accept|allow|agree|got\s?it|enable)\b", re.IGNORECASE)
    REJECT_RE = re.compile(
        r"\b(reject|decline|refuse|deny|disagree|necessary only|essential only|"
        r"only necessary|manage|customi[sz]e)\b", re.IGNORECASE)
    BANNER_HINT_RE = re.compile(r"cookie|consent|gdpr|privacy", re.IGNORECASE)
    PII_FIELD_RE = re.compile(
        r"email|e-mail|passwd|password|\btel\b|phone|name|address|card|cc-|"
        r"credit|cvv|ssn|social", re.IGNORECASE)

    def __init__(self) -> None:
        self._reported_trackers: set = set()
        self._first_page = True  # policy-link check runs once (homepage footer)

    def analyze(self, ctx: AnalyzerContext) -> List[Issue]:
        if ctx.status >= 400:
            return []
        issues: List[Issue] = []
        issues.extend(self._check_pre_consent_trackers(ctx))
        issues.extend(self._check_tracking_cookies(ctx))
        issues.extend(self._check_dark_patterns(ctx))
        issues.extend(self._check_policy_links(ctx))
        issues.extend(self._check_insecure_pii_forms(ctx))
        return issues

    # -- pre-consent third-party trackers ----------------------------------
    def _check_pre_consent_trackers(self, ctx: AnalyzerContext) -> List[Issue]:
        issues: List[Issue] = []
        hits: Dict[str, str] = {}
        for raw in ctx.network_requests:
            low = raw.lower()
            for fragment, vendor in self.TRACKER_HOSTS.items():
                if fragment in low:
                    hits.setdefault(vendor, raw)
                    break
        for vendor, sample in hits.items():
            key = ("req", vendor)
            if key in self._reported_trackers:
                continue
            self._reported_trackers.add(key)
            issues.append(Issue(
                SEVERITY_CRITICAL, CATEGORY_PRIVACY, "tracker-before-consent",
                f"Third-party tracker '{vendor}' fired before the user gave consent.",
                ctx.final_url,
                _truncate(sample, 160),
            ))
        return issues

    # -- pre-consent tracking cookies --------------------------------------
    def _check_tracking_cookies(self, ctx: AnalyzerContext) -> List[Issue]:
        issues: List[Issue] = []
        for cookie in ctx.cookies:
            name = (cookie.get("name") or "")
            domain = (cookie.get("domain") or "").lstrip(".").lower()
            for fragment, vendor in self.TRACKER_COOKIES.items():
                # Short/ambiguous names require an exact match.
                matched = (name == fragment) or (len(fragment) > 2 and name.startswith(fragment))
                if not matched:
                    continue
                key = ("cookie", vendor, name)
                if key in self._reported_trackers:
                    break
                self._reported_trackers.add(key)
                issues.append(Issue(
                    SEVERITY_CRITICAL, CATEGORY_PRIVACY, "third-party-cookie",
                    f"Tracking cookie '{name}' ({vendor}) was set before consent.",
                    ctx.final_url,
                    f"cookie domain: {domain or 'n/a'}",
                ))
                break
        return issues

    # -- cookie-banner dark patterns ---------------------------------------
    def _check_dark_patterns(self, ctx: AnalyzerContext) -> List[Issue]:
        banner = self._find_banner(ctx.soup)
        if banner is None:
            return []
        controls = banner.find_all(["button", "a"]) + banner.find_all(attrs={"role": "button"})
        accept = any(self.ACCEPT_RE.search(c.get_text(" ", strip=True) or "") for c in controls)
        reject = any(self.REJECT_RE.search(c.get_text(" ", strip=True) or "") for c in controls)
        if accept and not reject:
            return [Issue(
                SEVERITY_WARNING, CATEGORY_PRIVACY, "cookie-dark-pattern",
                "Cookie banner offers 'Accept' but no equally accessible 'Reject' control.",
                ctx.final_url,
                "GDPR Art. 7(3) and CPRA require refusing to be as easy as accepting.",
            )]
        return []

    def _find_banner(self, soup: BeautifulSoup):
        """Locate a consent banner by id/class hint, requiring an actionable control."""
        for el in soup.find_all(["div", "section", "aside", "dialog", "form"]):
            ident = (el.get("id") or "") + " " + " ".join(el.get("class") or [])
            if self.BANNER_HINT_RE.search(ident) and el.find(["button", "a"]):
                return el
        return None

    # -- privacy policy / terms links --------------------------------------
    def _check_policy_links(self, ctx: AnalyzerContext) -> List[Issue]:
        # Footer links are site-wide; assess only the first crawled page.
        if not self._first_page:
            return []
        self._first_page = False

        has_privacy = has_terms = False
        for a in ctx.soup.find_all("a", href=True):
            blob = ((a.get_text(" ", strip=True) or "") + " " + a["href"]).lower()
            if "privacy" in blob:
                has_privacy = True
            if "terms" in blob or "/tos" in blob or "conditions" in blob:
                has_terms = True

        issues: List[Issue] = []
        if not has_privacy:
            issues.append(Issue(
                SEVERITY_WARNING, CATEGORY_PRIVACY, "missing-privacy-policy",
                "No Privacy Policy link was found on the site.",
                ctx.final_url,
                "A published privacy notice is mandatory under GDPR and US state laws.",
            ))
        if not has_terms:
            issues.append(Issue(
                SEVERITY_INFO, CATEGORY_PRIVACY, "missing-terms",
                "No Terms of Service / Conditions link was found on the site.",
                ctx.final_url,
                "Terms strengthen your position in consumer disputes.",
            ))
        return issues

    # -- insecure PII forms -------------------------------------------------
    def _check_insecure_pii_forms(self, ctx: AnalyzerContext) -> List[Issue]:
        issues: List[Issue] = []
        page_insecure = not ctx.is_https
        for form in ctx.soup.find_all("form"):
            action = (form.get("action") or "").strip()
            action_insecure = action.lower().startswith("http://")
            if not (page_insecure or action_insecure):
                continue
            if self._form_captures_pii(form):
                issues.append(Issue(
                    SEVERITY_CRITICAL, CATEGORY_PRIVACY, "insecure-pii-form",
                    "A form collecting personal data is submitted over unencrypted HTTP.",
                    ctx.final_url,
                    f"form action: {action or '(same page)'}",
                ))
        return issues

    def _form_captures_pii(self, form) -> bool:
        for inp in form.find_all(["input", "textarea", "select"]):
            input_type = (inp.get("type") or "text").lower()
            if input_type in ("password", "email", "tel"):
                return True
            blob = " ".join(filter(None, [
                inp.get("name", ""), inp.get("id", ""),
                inp.get("autocomplete", ""), inp.get("placeholder", ""),
            ]))
            if self.PII_FIELD_RE.search(blob):
                return True
        return False


# ---------------------------------------------------------------------------
# Bug / runtime-error analyzer
# ---------------------------------------------------------------------------
class BugAnalyzer:
    """Turns Playwright console / network observations into issues."""

    def analyze(self, ctx: AnalyzerContext) -> List[Issue]:
        issues: List[Issue] = []

        # Uncaught JS exceptions are the most severe runtime problem.
        for err in ctx.page_errors:
            issues.append(Issue(
                SEVERITY_CRITICAL, CATEGORY_BUGS, "js-exception",
                "Uncaught JavaScript exception during page load.",
                ctx.final_url,
                _truncate(err.get("message", "")),
            ))

        # console.error() output (deduplicated by message).
        seen_console: set = set()
        for msg in ctx.console_errors:
            if msg.get("type") != "error":
                continue
            text = msg.get("text", "")
            if text in seen_console:
                continue
            seen_console.add(text)
            issues.append(Issue(
                SEVERITY_WARNING, CATEGORY_BUGS, "console-error",
                "Browser console error logged.",
                ctx.final_url,
                _truncate(text),
            ))

        # Failed network requests (blocked, DNS, 4xx/5xx sub-resources).
        seen_req: set = set()
        for req in ctx.failed_requests:
            url = req.get("url", "")
            if url in seen_req:
                continue
            seen_req.add(url)
            issues.append(Issue(
                SEVERITY_WARNING, CATEGORY_BUGS, "failed-request",
                "A network request failed while loading the page.",
                ctx.final_url,
                f"{req.get('failure', '')} {url}".strip(),
            ))
        return issues


# ---------------------------------------------------------------------------
# SEO analyzer
# ---------------------------------------------------------------------------
class SeoAnalyzer:
    """Technical-SEO checks that complement the Content & Accessibility modules.

    Title, meta-description and heading checks already live in
    :class:`ContentAnalyzer` / :class:`AccessibilityAnalyzer`. This module adds
    the *technical* search signals they do not cover: canonicalisation, the
    mobile viewport, indexability (robots), social / Open-Graph cards and
    structured data (schema.org). Its findings are operational - lost ranking
    and organic traffic - rather than legal liabilities.
    """

    def analyze(self, ctx: AnalyzerContext) -> List[Issue]:
        # Only audit successfully served HTML documents.
        if ctx.status >= 400:
            return []
        issues: List[Issue] = []
        issues.extend(self._check_canonical(ctx))
        issues.extend(self._check_viewport(ctx))
        issues.extend(self._check_robots(ctx))
        issues.extend(self._check_social(ctx))
        issues.extend(self._check_structured_data(ctx))
        return issues

    @staticmethod
    def _meta_content(ctx: AnalyzerContext, name: str) -> Optional[str]:
        """Return the stripped content of a <meta name=\"...\"> (case-insensitive)."""
        name = name.lower()
        for m in ctx.soup.find_all("meta"):
            if (m.get("name") or "").strip().lower() == name:
                return (m.get("content") or "").strip()
        return None

    # -- canonical URL ------------------------------------------------------
    def _check_canonical(self, ctx: AnalyzerContext) -> List[Issue]:
        for link in ctx.soup.find_all("link"):
            rels = [r.lower() for r in (link.get("rel") or [])]
            if "canonical" in rels and (link.get("href") or "").strip():
                return []
        return [Issue(
            SEVERITY_INFO, CATEGORY_SEO, "missing-canonical",
            "The page has no rel=\"canonical\" link.",
            ctx.final_url,
            "A canonical URL prevents duplicate-content dilution across "
            "parameter and variant URLs.",
        )]

    # -- mobile viewport ----------------------------------------------------
    def _check_viewport(self, ctx: AnalyzerContext) -> List[Issue]:
        if not self._meta_content(ctx, "viewport"):
            return [Issue(
                SEVERITY_WARNING, CATEGORY_SEO, "missing-viewport",
                "No responsive viewport meta tag was found.",
                ctx.final_url,
                "Google uses mobile-first indexing; add <meta name=\"viewport\" "
                "content=\"width=device-width, initial-scale=1\">.",
            )]
        return []

    # -- indexability (robots meta) ----------------------------------------
    def _check_robots(self, ctx: AnalyzerContext) -> List[Issue]:
        content = self._meta_content(ctx, "robots") or ""
        low = content.lower()
        if "noindex" in low:
            return [Issue(
                SEVERITY_WARNING, CATEGORY_SEO, "noindex",
                "The page is blocked from search engines (robots: noindex).",
                ctx.final_url,
                f"robots = {content[:120]!r}. Remove 'noindex' if it should rank.",
            )]
        if "nofollow" in low:
            return [Issue(
                SEVERITY_INFO, CATEGORY_SEO, "nofollow",
                "Every link on the page is marked 'nofollow' (robots meta).",
                ctx.final_url,
                f"robots = {content[:120]!r}.",
            )]
        return []

    # -- social / Open-Graph cards -----------------------------------------
    def _check_social(self, ctx: AnalyzerContext) -> List[Issue]:
        metas = ctx.soup.find_all("meta")
        has_og = any((m.get("property") or "").lower().startswith("og:") for m in metas)
        has_tw = any((m.get("name") or "").lower().startswith("twitter:") for m in metas)
        if not has_og and not has_tw:
            return [Issue(
                SEVERITY_INFO, CATEGORY_SEO, "missing-social-meta",
                "No Open Graph or Twitter Card metadata was found.",
                ctx.final_url,
                "Social cards control how the page looks when shared and lift "
                "click-through from social platforms.",
            )]
        return []

    # -- structured data ----------------------------------------------------
    def _check_structured_data(self, ctx: AnalyzerContext) -> List[Issue]:
        has_jsonld = any(
            (s.get("type") or "").strip().lower() == "application/ld+json"
            for s in ctx.soup.find_all("script")
        )
        has_microdata = ctx.soup.find(attrs={"itemscope": True}) is not None
        has_rdfa = ctx.soup.find(attrs={"typeof": True}) is not None
        if not (has_jsonld or has_microdata or has_rdfa):
            return [Issue(
                SEVERITY_INFO, CATEGORY_SEO, "missing-structured-data",
                "No structured data (JSON-LD / microdata) was detected.",
                ctx.final_url,
                "Schema.org markup enables rich results (ratings, FAQs, "
                "breadcrumbs) in search listings.",
            )]
        return []


# ---------------------------------------------------------------------------
# Module level helpers
# ---------------------------------------------------------------------------
def _redact(secret: str) -> str:
    """Show only the first few characters of a detected secret."""
    secret = secret.strip()
    if len(secret) <= 8:
        return secret[:2] + "***"
    return f"{secret[:4]}...{secret[-2:]} (redacted)"


def _looks_like_placeholder(value: str) -> bool:
    """Filter obvious non-secret placeholder values to reduce false positives."""
    low = value.lower()
    placeholders = (
        "your", "example", "changeme", "placeholder", "xxxx", "0000",
        "test", "dummy", "none", "null", "undefined", "{{", "}}", "<%",
    )
    return any(p in low for p in placeholders)


def _truncate(text: str, limit: int = 300) -> str:
    text = (text or "").strip().replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def _visible_text(soup: BeautifulSoup) -> str:
    """Extract human-visible text, ignoring scripts, styles and noscript."""
    parts: List[str] = []
    for element in soup.find_all(string=True):
        parent = element.parent.name if element.parent else ""
        if parent in {"script", "style", "noscript", "template"}:
            continue
        stripped = element.strip()
        if stripped:
            parts.append(stripped)
    return " ".join(parts)


def _tokens_overlap(a: str, b: str) -> bool:
    """True if two strings share at least one meaningful (4+ char) token."""
    stop = {"the", "and", "for", "with", "your", "from", "this", "that", "home", "page"}
    ta = {w for w in re.findall(r"[a-z0-9]+", a.lower()) if len(w) >= 4 and w not in stop}
    tb = {w for w in re.findall(r"[a-z0-9]+", b.lower()) if len(w) >= 4 and w not in stop}
    if not ta or not tb:
        return True  # not enough signal -> do not flag
    return bool(ta & tb)


# Keywords that qualify a "<N> day" phrase as a refund/return promise.
_REFUND_KEYWORDS = ("refund", "return", "money-back", "money back", "guarantee",
                    "cancel", "trial")
_REFUND_RE = re.compile(r"(\d{1,3})\s*-?\s*day", re.IGNORECASE)
_PLAN_PRICE_RE = re.compile(
    r"\b(basic|starter|standard|pro|plus|premium|business|enterprise|team)\b"
    r"[^$]{0,40}\$\s?(\d{1,4}(?:\.\d{2})?)",
    re.IGNORECASE,
)


def _extract_refund_windows(text: str) -> set:
    """Return the set of distinct refund/return windows (in days) mentioned."""
    low = text.lower()
    windows: set = set()
    for m in _REFUND_RE.finditer(low):
        days = int(m.group(1))
        if days == 0 or days > 365:
            continue
        surrounding = low[max(0, m.start() - 45): m.end() + 45]
        if any(k in surrounding for k in _REFUND_KEYWORDS):
            windows.add(days)
    return windows


def _extract_plan_prices(text: str) -> Dict[str, str]:
    """Return a ``{plan_name: price}`` map heuristically parsed from the page."""
    found: Dict[str, str] = {}
    for m in _PLAN_PRICE_RE.finditer(text):
        plan = m.group(1).lower()
        found.setdefault(plan, m.group(2))
    return found


def _count_syllables(word: str) -> int:
    """Rough English syllable counter used by the readability heuristic."""
    word = word.lower()
    if not word:
        return 0
    vowels = "aeiouy"
    count = 0
    prev_is_vowel = False
    for ch in word:
        is_vowel = ch in vowels
        if is_vowel and not prev_is_vowel:
            count += 1
        prev_is_vowel = is_vowel
    # Silent trailing 'e' (e.g. "make") usually does not add a syllable.
    if word.endswith("e") and count > 1:
        count -= 1
    return max(count, 1)


def _flesch_reading_ease(text: str, words: List[str]) -> Optional[float]:
    """Compute the Flesch Reading Ease score (higher == easier).

    Returns ``None`` when there is not enough text to produce a stable score.
    """
    sentences = [s for s in re.split(r"[.!?]+", text) if s.strip()]
    num_sentences = max(len(sentences), 1)
    num_words = len(words)
    if num_words < 30:
        return None
    num_syllables = sum(_count_syllables(w) for w in words)
    score = (
        206.835
        - 1.015 * (num_words / num_sentences)
        - 84.6 * (num_syllables / num_words)
    )
    # Clamp to the conventional 0-100 reporting range.
    return max(0.0, min(100.0, score))


# ---------------------------------------------------------------------------
# Legal & financial mapping
# ---------------------------------------------------------------------------
# Indicative repercussions are illustrative, not legal advice. They translate a
# technical finding into the regulation(s) it implicates and a plausible
# financial / operational consequence so non-technical stakeholders can triage.
_A11Y_LAW = "ADA Title III (US); Section 508; European Accessibility Act (EAA)"
_A11Y_PEN = ("Civil demand letters & DOJ enforcement; EU market product bans; "
             "typical accessibility settlements $5,000-$50,000+ per claim.")
_SEC_LAW = "FTC Act \u00a7 5 (failure to maintain reasonable security)"
_SEC_PEN = ("FTC enforcement actions and heightened breach-notification "
            "class-action exposure if exploited.")
_PRIV_TRACK_LAW = "GDPR Art. 6/7; ePrivacy Directive; CCPA/CPRA; CIPA (wiretapping)"
_PRIV_TRACK_PEN = ("CIPA statutory damages $5,000 per violation; GDPR fines up "
                   "to 4% of global annual turnover.")
_UDAP_LAW = "State UDAP statutes; FTC Act \u00a7 5 (deceptive practices); false advertising"
_UDAP_PEN = "Class-action exposure, restitution and civil penalties."
_SEO_PEN = ("Operational: lost conversions, user-retention damage and Google "
            "Core Web Vitals SEO penalties.")

# Per-issue-type mapping: type -> (law, penalty). Falls back to category default.
LEGAL_MAP: Dict[str, Tuple[str, str]] = {
    # Accessibility (WCAG 2.2)
    "missing-lang": (_A11Y_LAW, _A11Y_PEN),
    "missing-title": (_A11Y_LAW, _A11Y_PEN),
    "img-missing-alt": (_A11Y_LAW, _A11Y_PEN),
    "missing-h1": (_A11Y_LAW, _A11Y_PEN),
    "multiple-h1": (_A11Y_LAW, _A11Y_PEN),
    "skipped-heading-level": (_A11Y_LAW, _A11Y_PEN),
    "vague-link-text": (_A11Y_LAW, _A11Y_PEN),
    "empty-link": (_A11Y_LAW, _A11Y_PEN),
    "form-missing-label": (_A11Y_LAW, _A11Y_PEN),
    "missing-landmark": (_A11Y_LAW, _A11Y_PEN),
    "target-size": (_A11Y_LAW, _A11Y_PEN),
    # Privacy
    "tracker-before-consent": (_PRIV_TRACK_LAW, _PRIV_TRACK_PEN),
    "third-party-cookie": (_PRIV_TRACK_LAW, _PRIV_TRACK_PEN),
    "cookie-dark-pattern": (
        "GDPR Art. 7(3); CPRA \u00a7 1798.135; EDPB dark-pattern guidelines",
        "Invalidated consent, regulator fines and CPRA enforcement actions."),
    "missing-privacy-policy": (
        "CCPA/CPRA \u00a7 1798.130; GDPR Art. 13/14; VCDPA; Texas TDPSA",
        "Regulatory fines and per-consumer statutory penalties."),
    "missing-terms": (_UDAP_LAW, "Weakened contractual position in consumer disputes."),
    "insecure-pii-form": (
        "GDPR Art. 32 (security of processing); FTC Act \u00a7 5",
        "Breach liability, FTC enforcement and class-action statutory damages."),
    # Security
    "missing-security-header": (_SEC_LAW, _SEC_PEN),
    "weak-security-header": (_SEC_LAW, _SEC_PEN),
    "mixed-content": (
        "FTC Act \u00a7 5; PCI-DSS (where payment data is involved)",
        "Data-integrity risk, browser blocking and breach exposure."),
    "exposed-secret": (
        "FTC Act \u00a7 5; breach-notification statutes (e.g. CCPA \u00a7 1798.150)",
        "CCPA breach damages $100-$750 per consumer per incident; FTC action."),
    "exposed-env-var": (
        "FTC Act \u00a7 5; breach-notification statutes (e.g. CCPA \u00a7 1798.150)",
        "CCPA breach damages $100-$750 per consumer per incident; FTC action."),
    "staging-url": (_SEC_LAW, "Expanded attack surface and information disclosure."),
    "sensitive-path": (_SEC_LAW, "Increased attack surface and breach exposure."),
    # Content integrity
    "refund-contradiction": (_UDAP_LAW, _UDAP_PEN),
    "price-contradiction": (_UDAP_LAW, _UDAP_PEN),
    "llm-contradiction": (_UDAP_LAW, _UDAP_PEN),
    "placeholder-text": ("", "Brand/quality risk; not a direct legal liability."),
    # SEO (technical - operational impact, not a direct legal liability)
    "missing-canonical": ("", _SEO_PEN),
    "missing-viewport": ("", _SEO_PEN),
    "noindex": ("", _SEO_PEN),
    "nofollow": ("", _SEO_PEN),
    "missing-social-meta": ("", _SEO_PEN),
    "missing-structured-data": ("", _SEO_PEN),
}

# Category-level fallback when a specific type is not mapped above.
CATEGORY_LEGAL_DEFAULT: Dict[str, Tuple[str, str]] = {
    CATEGORY_ACCESSIBILITY: (_A11Y_LAW, _A11Y_PEN),
    CATEGORY_PRIVACY: (_PRIV_TRACK_LAW, _PRIV_TRACK_PEN),
    CATEGORY_SECURITY: (_SEC_LAW, _SEC_PEN),
    CATEGORY_CONTENT: ("", _SEO_PEN),
    CATEGORY_SEO: ("", _SEO_PEN),
    CATEGORY_BUGS: ("", _SEO_PEN),
    CATEGORY_DEAD_LINKS: ("", _SEO_PEN),
}


def annotate_legal(issue: Issue) -> Issue:
    """Populate ``issue.law`` / ``issue.penalty`` from the catalog (in place)."""
    law, penalty = LEGAL_MAP.get(issue.type, (None, None))
    if law is None:
        law, penalty = CATEGORY_LEGAL_DEFAULT.get(issue.category, ("", ""))
    if not issue.law:
        issue.law = law
    if not issue.penalty:
        issue.penalty = penalty
    return issue


# ---------------------------------------------------------------------------
# Legal & Compliance Risk Index
# ---------------------------------------------------------------------------
SEVERITY_WEIGHT = {SEVERITY_CRITICAL: 10, SEVERITY_WARNING: 4, SEVERITY_INFO: 1}
CATEGORY_MULTIPLIER = {
    CATEGORY_PRIVACY: 1.5,
    CATEGORY_SECURITY: 1.4,
    CATEGORY_ACCESSIBILITY: 1.3,
    CATEGORY_CONTENT: 1.2,
    CATEGORY_SEO: 0.9,
    CATEGORY_DEAD_LINKS: 1.0,
    CATEGORY_BUGS: 0.8,
}

# Canonical regulation buckets and the substrings that map a law string to them.
REGULATION_CANON = [
    ("ADA Title III", ["ADA Title III"]),
    ("Section 508", ["Section 508"]),
    ("EAA", ["European Accessibility Act", "EAA"]),
    ("GDPR", ["GDPR"]),
    ("ePrivacy", ["ePrivacy"]),
    ("CCPA/CPRA", ["CCPA", "CPRA"]),
    ("VCDPA", ["VCDPA"]),
    ("Texas TDPSA", ["TDPSA"]),
    ("CIPA", ["CIPA"]),
    ("FTC Act", ["FTC Act"]),
    ("UDAP", ["UDAP"]),
    ("PCI-DSS", ["PCI-DSS"]),
]


def _grade_for(score: int) -> Tuple[str, str]:
    """Map a 0-100 risk score (higher == worse) to a letter grade and label."""
    if score < 10:
        return "A", "Low"
    if score < 25:
        return "B", "Guarded"
    if score < 45:
        return "C", "Elevated"
    if score < 70:
        return "D", "High"
    return "F", "Severe"


def compute_risk(issues: List[dict]) -> dict:
    """Roll a list of issue dicts up into the Legal & Compliance Risk Index."""
    total = 0.0
    by_category: Dict[str, float] = {}
    by_regulation: Dict[str, int] = {}
    counts = {SEVERITY_CRITICAL: 0, SEVERITY_WARNING: 0, SEVERITY_INFO: 0}

    for it in issues:
        sev = it.get("severity", SEVERITY_INFO)
        cat = it.get("category", "")
        law = it.get("law", "") or ""
        counts[sev] = counts.get(sev, 0) + 1
        weight = SEVERITY_WEIGHT.get(sev, 1) * CATEGORY_MULTIPLIER.get(cat, 1.0)
        total += weight
        by_category[cat] = round(by_category.get(cat, 0.0) + weight, 1)
        for canon, tokens in REGULATION_CANON:
            if any(tok in law for tok in tokens):
                by_regulation[canon] = by_regulation.get(canon, 0) + 1

    # Diminishing-returns curve so a handful of criticals already reads "high".
    score = 0 if not issues else round(100 * (1 - math.exp(-total / 60.0)))
    score = max(0, min(100, score))
    grade, level = _grade_for(score)
    top_regulations = sorted(by_regulation.items(), key=lambda kv: -kv[1])[:6]

    return {
        "score": score,
        "grade": grade,
        "level": level,
        "total_weight": round(total, 1),
        "counts": counts,
        "by_category": by_category,
        "by_regulation": by_regulation,
        "top_regulations": top_regulations,
        "headline": (
            f"{counts.get(SEVERITY_CRITICAL, 0)} critical and "
            f"{counts.get(SEVERITY_WARNING, 0)} warning findings indicate "
            f"{level.lower()} legal & compliance exposure."
        ),
    }


# ---------------------------------------------------------------------------
# Per-category ranking (normalised by site size)
# ---------------------------------------------------------------------------
# Grade thresholds for issue *density* - the severity-weighted number of
# findings per crawled page. Normalising by page count means the same raw count
# is judged more harshly on a small site than on a large one.
_DENSITY_GRADES = [
    (1.0, "A", "Excellent"),
    (3.0, "B", "Good"),
    (6.0, "C", "Fair"),
    (12.0, "D", "Poor"),
]


def _density_grade(density: float) -> Tuple[str, str]:
    """Map a severity-weighted issues-per-page value to a grade and label."""
    for threshold, grade, label in _DENSITY_GRADES:
        if density < threshold:
            return grade, label
    return "F", "Critical"


def compute_category_ranks(issues: List[dict], page_count: int) -> dict:
    """Rank each category by severity-weighted issue density (per crawled page).

    Dividing each category's weighted issue load by the number of pages crawled
    means the ranking reflects the *size* of the site, not just raw counts: ten
    issues on a two-page site is far worse than ten across two hundred pages.

    Returns a dict with a ``categories`` list ordered worst-first (rank 1 == the
    highest-risk category for the site's size), the page count used for the
    normalisation, and the worst / best category names.
    """
    pages = max(int(page_count or 0), 1)
    buckets: Dict[str, dict] = {}
    for it in issues:
        cat = it.get("category", "Other")
        sev = it.get("severity", SEVERITY_INFO)
        entry = buckets.setdefault(
            cat, {"count": 0, "weight": 0.0,
                  SEVERITY_CRITICAL: 0, SEVERITY_WARNING: 0, SEVERITY_INFO: 0})
        entry["count"] += 1
        entry[sev] = entry.get(sev, 0) + 1
        entry["weight"] += SEVERITY_WEIGHT.get(sev, 1)

    ranked: List[dict] = []
    for cat, e in buckets.items():
        density = e["weight"] / pages
        grade, label = _density_grade(density)
        ranked.append({
            "category": cat,
            "count": e["count"],
            "critical": e[SEVERITY_CRITICAL],
            "warning": e[SEVERITY_WARNING],
            "info": e[SEVERITY_INFO],
            "weight": round(e["weight"], 1),
            "density": round(density, 2),
            "grade": grade,
            "label": label,
        })

    ranked.sort(key=lambda r: (-r["density"], -r["weight"], r["category"]))
    for i, row in enumerate(ranked, start=1):
        row["rank"] = i

    return {
        "pages": pages,
        "categories": ranked,
        "worst": ranked[0]["category"] if ranked else None,
        "best": ranked[-1]["category"] if ranked else None,
    }


# Registry used by the crawler to map a module key -> analyzer class.
ANALYZER_REGISTRY = {
    "security": SecurityAnalyzer,
    "accessibility": AccessibilityAnalyzer,
    "privacy": PrivacyAnalyzer,
    "content": ContentAnalyzer,
    "seo": SeoAnalyzer,
    "bugs": BugAnalyzer,
}
