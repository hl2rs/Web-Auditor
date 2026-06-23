"""
report_pdf.py
=============
Render a scan's full report (the dict produced by ``ScanJob.full_report``) into
an in-depth, multi-section PDF using ReportLab.

Document outline
----------------
1. Cover page - target, scan metadata and the headline Legal & Compliance Risk
   Index (score / grade / level) on a colour-coded band.
2. Executive summary - severity counts, weighted risk per category and the top
   regulations implicated.
3. Methodology & scope - modules executed, crawl budget and disclaimer.
4. Detailed findings - one table per category mapping each technical error to
   its affected URL, the specific law violated and the estimated repercussion.
5. Crawled-pages appendix.

The module is intentionally free of any Flask/web concerns so it can be reused
from a CLI or scheduled job.
"""

from __future__ import annotations

from datetime import datetime
from io import BytesIO
from typing import Dict, List
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ---------------------------------------------------------------------------
# Palette & constants
# ---------------------------------------------------------------------------
COLOR_CRITICAL = colors.HexColor("#e11d48")
COLOR_WARNING = colors.HexColor("#d97706")
COLOR_INFO = colors.HexColor("#0284c7")
COLOR_INK = colors.HexColor("#0f172a")
COLOR_MUTED = colors.HexColor("#475569")
COLOR_LINE = colors.HexColor("#cbd5e1")
COLOR_HEADER_BG = colors.HexColor("#0f172a")
COLOR_ZEBRA = colors.HexColor("#f1f5f9")

SEVERITY_COLOR = {
    "Critical": COLOR_CRITICAL,
    "Warning": COLOR_WARNING,
    "Info": COLOR_INFO,
}
SEVERITY_ORDER = {"Critical": 0, "Warning": 1, "Info": 2}

# Colour band for the overall risk grade (higher score == worse == hotter).
LEVEL_COLOR = {
    "Low": colors.HexColor("#16a34a"),
    "Guarded": colors.HexColor("#65a30d"),
    "Elevated": colors.HexColor("#ca8a04"),
    "High": colors.HexColor("#ea580c"),
    "Severe": colors.HexColor("#dc2626"),
}

# Colour for each per-category letter grade (A best -> F worst).
GRADE_COLOR = {
    "A": colors.HexColor("#16a34a"),
    "B": colors.HexColor("#65a30d"),
    "C": colors.HexColor("#ca8a04"),
    "D": colors.HexColor("#ea580c"),
    "F": colors.HexColor("#dc2626"),
}

# Order in which category sections appear in the detailed findings.
CATEGORY_ORDER = ["Security", "Privacy", "Accessibility", "SEO", "Dead Links", "Content", "Bugs"]

# Safety caps so a huge scan cannot produce an unwieldy document.
MAX_ISSUES_IN_PDF = 800
MAX_PAGES_IN_PDF = 250


def _styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle("title", parent=base["Title"], fontSize=26,
                                 textColor=COLOR_INK, leading=30, spaceAfter=6),
        "subtitle": ParagraphStyle("subtitle", parent=base["Normal"], fontSize=12,
                                    textColor=COLOR_MUTED, alignment=TA_CENTER),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=15,
                             textColor=COLOR_INK, spaceBefore=14, spaceAfter=6),
        "h3": ParagraphStyle("h3", parent=base["Heading3"], fontSize=12,
                             textColor=COLOR_INK, spaceBefore=8, spaceAfter=4),
        "body": ParagraphStyle("body", parent=base["Normal"], fontSize=9.5,
                               textColor=COLOR_INK, leading=13),
        "muted": ParagraphStyle("muted", parent=base["Normal"], fontSize=8.5,
                                textColor=COLOR_MUTED, leading=12),
        "cell": ParagraphStyle("cell", parent=base["Normal"], fontSize=8,
                               textColor=COLOR_INK, leading=10.5),
        "cell_head": ParagraphStyle("cell_head", parent=base["Normal"], fontSize=8.5,
                                    textColor=colors.white, leading=11),
        "url": ParagraphStyle("url", parent=base["Normal"], fontSize=7.2,
                              textColor=colors.HexColor("#1d4ed8"), leading=9.5),
        "big_score": ParagraphStyle("big_score", parent=base["Title"], fontSize=54,
                                    textColor=colors.white, alignment=TA_CENTER, leading=56),
        "band_label": ParagraphStyle("band_label", parent=base["Normal"], fontSize=11,
                                     textColor=colors.white, alignment=TA_CENTER, leading=14),
    }
    return styles


def esc(value) -> str:
    """XML-escape any dynamic (possibly attacker-controlled) text for ReportLab."""
    return escape(str(value if value is not None else ""))


def _sev_para(severity: str, styles) -> Paragraph:
    color = SEVERITY_COLOR.get(severity, COLOR_INFO)
    return Paragraph(
        f'<font color="{color.hexval()}"><b>{esc(severity)}</b></font>',
        styles["cell"],
    )


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------
def _cover(report: dict, risk: dict, styles) -> List:
    story: List = [Spacer(1, 22 * mm)]
    story.append(Paragraph("Compliance Risk Audit", styles["title"]))
    story.append(Paragraph("Auditor &#183; Digital Compliance Report", styles["subtitle"]))
    story.append(Spacer(1, 10 * mm))

    # Risk band -------------------------------------------------------------
    level = risk.get("level", "Low")
    band_color = LEVEL_COLOR.get(level, COLOR_INFO)
    score = risk.get("score", 0)
    grade = risk.get("grade", "A")
    band_inner = Table(
        [[Paragraph(f"{score}", styles["big_score"])],
         [Paragraph(f"Grade {esc(grade)} &middot; {esc(level)} Risk", styles["band_label"])],
         [Paragraph("Legal &amp; Compliance Risk Index (0 = clean, 100 = severe)",
                    styles["band_label"])]],
        colWidths=[150 * mm],
    )
    band_inner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), band_color),
        ("TOPPADDING", (0, 0), (-1, 0), 12),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 12),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    story.append(band_inner)
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph(esc(risk.get("headline", "")), styles["body"]))
    story.append(Spacer(1, 10 * mm))

    # Metadata table --------------------------------------------------------
    generated = report.get("generated_at", "")
    try:
        generated = datetime.fromisoformat(generated).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        pass
    cfg = report.get("config", {})
    meta = [
        ["Target", esc(report.get("start_url", ""))],
        ["Scan ID", esc(report.get("id", ""))],
        ["Status", esc(report.get("status", "")).title()],
        ["Generated", esc(generated)],
        ["Pages crawled", esc(len(report.get("pages", [])))],
        ["Total findings", esc(report.get("summary", {}).get("total", 0))],
        ["Modules", esc(", ".join(cfg.get("modules", [])))],
        ["Crawl budget", esc(f"depth {cfg.get('max_depth')} / max {cfg.get('max_pages')} pages")],
        ["Duration", esc(f"{report.get('elapsed_seconds', 0)}s")],
    ]
    rows = [[Paragraph(f"<b>{k}</b>", styles["cell"]), Paragraph(v, styles["cell"])]
            for k, v in meta]
    meta_table = Table(rows, colWidths=[40 * mm, 110 * mm])
    meta_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, COLOR_LINE),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, COLOR_ZEBRA]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph(
        "This report is generated by automated heuristics and is provided for "
        "informational purposes only. It does not constitute legal advice; "
        "consult qualified counsel for compliance decisions.", styles["muted"]))
    story.append(PageBreak())
    return story


def _summary(report: dict, risk: dict, styles) -> List:
    story: List = [Paragraph("Executive Summary", styles["h2"]),
                   HRFlowable(width="100%", color=COLOR_LINE, spaceAfter=8)]

    counts = risk.get("counts", {})
    severity_table = Table(
        [[Paragraph("<b>Critical</b>", styles["cell_head"]),
          Paragraph("<b>Warning</b>", styles["cell_head"]),
          Paragraph("<b>Info</b>", styles["cell_head"]),
          Paragraph("<b>Total</b>", styles["cell_head"])],
         [Paragraph(str(counts.get("Critical", 0)), styles["cell"]),
          Paragraph(str(counts.get("Warning", 0)), styles["cell"]),
          Paragraph(str(counts.get("Info", 0)), styles["cell"]),
          Paragraph(str(report.get("summary", {}).get("total", 0)), styles["cell"])]],
        colWidths=[45 * mm, 45 * mm, 45 * mm, 45 * mm],
    )
    severity_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), COLOR_CRITICAL),
        ("BACKGROUND", (1, 0), (1, 0), COLOR_WARNING),
        ("BACKGROUND", (2, 0), (2, 0), COLOR_INFO),
        ("BACKGROUND", (3, 0), (3, 0), COLOR_INK),
        ("GRID", (0, 0), (-1, -1), 0.5, COLOR_LINE),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("FONTSIZE", (0, 1), (-1, 1), 13),
    ]))
    story.append(severity_table)
    story.append(Spacer(1, 6 * mm))

    # Weighted risk per category.
    by_category = risk.get("by_category", {})
    if by_category:
        story.append(Paragraph("Weighted risk by category", styles["h3"]))
        rows = [[Paragraph("<b>Category</b>", styles["cell_head"]),
                 Paragraph("<b>Risk weight</b>", styles["cell_head"])]]
        for cat, weight in sorted(by_category.items(), key=lambda kv: -kv[1]):
            rows.append([Paragraph(esc(cat), styles["cell"]),
                         Paragraph(esc(weight), styles["cell"])])
        cat_table = Table(rows, colWidths=[120 * mm, 60 * mm])
        cat_table.setStyle(_simple_table_style())
        story.append(cat_table)
        story.append(Spacer(1, 6 * mm))

    # Top regulations implicated.
    top_regs = risk.get("top_regulations", [])
    story.append(Paragraph("Top regulations implicated", styles["h3"]))
    if top_regs:
        rows = [[Paragraph("<b>Regulation / Standard</b>", styles["cell_head"]),
                 Paragraph("<b>Findings</b>", styles["cell_head"])]]
        for name, count in top_regs:
            rows.append([Paragraph(esc(name), styles["cell"]),
                         Paragraph(esc(count), styles["cell"])])
        reg_table = Table(rows, colWidths=[140 * mm, 40 * mm])
        reg_table.setStyle(_simple_table_style())
        story.append(reg_table)
    else:
        story.append(Paragraph("No regulated findings were detected.", styles["body"]))

    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("Scope &amp; Methodology", styles["h3"]))
    story.append(Paragraph(
        "Each page was rendered in a headless Chromium browser (executing "
        "JavaScript), parsed, and evaluated by the enabled analysis modules. "
        "Cookies were cleared before every navigation so any tracker or cookie "
        "observed is recorded in its pre-consent state. Links were verified with "
        "an asynchronous HTTP client. Findings are de-duplicated site-wide and "
        "mapped to the regulation(s) they implicate.", styles["body"]))
    story.append(PageBreak())
    return story


def _category_ranking(report: dict, styles) -> List:
    """Rank every category by severity-weighted issue density (per crawled page).

    Normalising by the number of pages crawled means the grade reflects the size
    of the site rather than raw counts, so small sites with a handful of serious
    issues are scored appropriately.
    """
    ranks = report.get("category_ranks") or {}
    cats = ranks.get("categories", [])
    pages = ranks.get("pages") or len(report.get("pages", [])) or 1

    story: List = [Paragraph("Category Risk Ranking", styles["h2"]),
                   HRFlowable(width="100%", color=COLOR_LINE, spaceAfter=8)]
    story.append(Paragraph(
        f"Each category is graded on <b>issue density</b> &mdash; the "
        f"severity-weighted number of findings per crawled page ({esc(pages)} "
        f"page(s) scanned) &mdash; and ordered worst-first (rank&nbsp;1 = the "
        f"highest-risk category for a site of this size). Grades: "
        f"A&nbsp;Excellent, B&nbsp;Good, C&nbsp;Fair, D&nbsp;Poor, F&nbsp;Critical.",
        styles["body"]))
    story.append(Spacer(1, 4 * mm))

    if not cats:
        story.append(Paragraph("No issues were detected, so there is nothing to "
                               "rank. The site passed every enabled check.",
                               styles["body"]))
        story.append(PageBreak())
        return story

    header = [
        Paragraph("<b>#</b>", styles["cell_head"]),
        Paragraph("<b>Category</b>", styles["cell_head"]),
        Paragraph("<b>Grade</b>", styles["cell_head"]),
        Paragraph("<b>Critical</b>", styles["cell_head"]),
        Paragraph("<b>Warning</b>", styles["cell_head"]),
        Paragraph("<b>Info</b>", styles["cell_head"]),
        Paragraph("<b>Total</b>", styles["cell_head"]),
        Paragraph("<b>Risk / Page</b>", styles["cell_head"]),
    ]
    data = [header]
    for c in cats:
        grade = c.get("grade", "A")
        color = GRADE_COLOR.get(grade, COLOR_INFO)
        data.append([
            Paragraph(esc(c.get("rank", "")), styles["cell"]),
            Paragraph(f"<b>{esc(c.get('category', ''))}</b>", styles["cell"]),
            Paragraph(
                f'<font color="{color.hexval()}"><b>{esc(grade)} &middot; '
                f'{esc(c.get("label", ""))}</b></font>', styles["cell"]),
            Paragraph(esc(c.get("critical", 0)), styles["cell"]),
            Paragraph(esc(c.get("warning", 0)), styles["cell"]),
            Paragraph(esc(c.get("info", 0)), styles["cell"]),
            Paragraph(esc(c.get("count", 0)), styles["cell"]),
            Paragraph(esc(c.get("density", 0)), styles["cell"]),
        ])
    table = Table(
        data,
        colWidths=[9 * mm, 39 * mm, 46 * mm, 18 * mm, 18 * mm, 14 * mm, 14 * mm, 22 * mm],
        repeatRows=1,
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_HEADER_BG),
        ("GRID", (0, 0), (-1, -1), 0.4, COLOR_LINE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_ZEBRA]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (3, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(table)

    worst = ranks.get("worst")
    if worst:
        story.append(Spacer(1, 4 * mm))
        story.append(Paragraph(
            f"<b>{esc(worst)}</b> carries the highest risk relative to this "
            f"site's size and should be remediated first.", styles["muted"]))
    story.append(PageBreak())
    return story


def _detailed_findings(report: dict, styles) -> List:
    story: List = [Paragraph("Detailed Findings", styles["h2"]),
                   HRFlowable(width="100%", color=COLOR_LINE, spaceAfter=8)]

    issues = report.get("issues", [])[:MAX_ISSUES_IN_PDF]
    grouped: Dict[str, List[dict]] = {}
    for issue in issues:
        grouped.setdefault(issue.get("category", "Other"), []).append(issue)

    if not issues:
        story.append(Paragraph("No issues were detected. The site passed all "
                               "enabled checks.", styles["body"]))
        return story

    ordered_categories = [c for c in CATEGORY_ORDER if c in grouped]
    ordered_categories += [c for c in grouped if c not in CATEGORY_ORDER]

    header = [
        Paragraph("<b>Severity</b>", styles["cell_head"]),
        Paragraph("<b>Technical Error</b>", styles["cell_head"]),
        Paragraph("<b>Affected URL</b>", styles["cell_head"]),
        Paragraph("<b>Law / Standard</b>", styles["cell_head"]),
        Paragraph("<b>Estimated Repercussion</b>", styles["cell_head"]),
    ]
    col_widths = [16 * mm, 52 * mm, 34 * mm, 38 * mm, 40 * mm]

    for category in ordered_categories:
        bucket = sorted(grouped[category],
                        key=lambda i: SEVERITY_ORDER.get(i.get("severity"), 9))
        story.append(Paragraph(f"{esc(category)} &nbsp;"
                               f"<font color='#64748b'>({len(bucket)})</font>",
                               styles["h3"]))
        data = [header]
        for it in bucket:
            message = esc(it.get("message", ""))
            details = esc(it.get("details", ""))
            tech = message
            if details:
                tech += f"<br/><font color='#64748b' size='7'>{details}</font>"
            data.append([
                _sev_para(it.get("severity", "Info"), styles),
                Paragraph(tech, styles["cell"]),
                Paragraph(esc(it.get("url", "")), styles["url"]),
                Paragraph(esc(it.get("law", "") or "&mdash;"), styles["cell"]),
                Paragraph(esc(it.get("penalty", "") or "&mdash;"), styles["cell"]),
            ])
        table = Table(data, colWidths=col_widths, repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_HEADER_BG),
            ("GRID", (0, 0), (-1, -1), 0.4, COLOR_LINE),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_ZEBRA]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(table)
        story.append(Spacer(1, 5 * mm))

    if len(report.get("issues", [])) > MAX_ISSUES_IN_PDF:
        story.append(Paragraph(
            f"Note: showing the first {MAX_ISSUES_IN_PDF} of "
            f"{len(report['issues'])} findings. Export JSON for the full set.",
            styles["muted"]))
    return story


# Plain-English remediation guidance for the most common Info-level findings.
# Falls back to the issue's own ``details`` text when a type is not listed here.
INFO_GUIDANCE = {
    "short-title": "Expand the title toward 50-60 characters using the page's primary keywords.",
    "long-title": "Trim the title under ~60 characters so it is not truncated in search results.",
    "missing-meta-description": "Add a unique 50-160 character meta description summarising the page.",
    "short-meta-description": "Lengthen the description toward ~150 characters to fill the search snippet.",
    "long-meta-description": "Shorten the description under ~160 characters to avoid truncation.",
    "thin-content": "Add substantive, original copy so the page offers clear value to visitors.",
    "low-readability": "Use shorter sentences and simpler words to make the copy easier to read.",
    "title-h1-mismatch": "Align the <title> and the main <h1> around the same primary topic.",
    "multiple-h1": "Keep a single <h1> per page and demote the others to <h2>/<h3>.",
    "missing-canonical": "Add a rel=\"canonical\" link to consolidate duplicate / variant URLs.",
    "missing-social-meta": "Add Open Graph and Twitter Card tags for richer social-share previews.",
    "missing-structured-data": "Add schema.org JSON-LD to qualify for rich results in search.",
    "nofollow": "Confirm the page-wide 'nofollow' is intentional - it blocks link equity.",
    "missing-terms": "Publish a Terms of Service page to strengthen your position in disputes.",
    "weak-security-header": "Set the header to its recommended secure value (e.g. 'nosniff').",
    "sensitive-path": "Review whether this path should be publicly linked; restrict access if not.",
}


def _informational_findings(report: dict, styles) -> List:
    """Go over every Info-severity finding, aggregated by type, with guidance.

    The detailed-findings tables list each Info issue inline with the more severe
    ones; this section pulls them together so the lower-priority, best-practice
    items get an explicit review with a recommended action and example page.
    """
    info = [i for i in report.get("issues", []) if i.get("severity") == "Info"]
    story: List = [PageBreak(),
                   Paragraph("Informational Findings", styles["h2"]),
                   HRFlowable(width="100%", color=COLOR_LINE, spaceAfter=8)]
    if not info:
        story.append(Paragraph(
            "No informational findings were recorded for this scan.", styles["body"]))
        return story

    story.append(Paragraph(
        f"These {len(info)} lower-priority observations are unlikely to cause "
        "immediate harm, but resolving them improves SEO, usability, security "
        "posture and overall quality. They are grouped by type below, each with "
        "the recommended action and an example affected page.", styles["body"]))
    story.append(Spacer(1, 4 * mm))

    # Aggregate by (category, type): count instances, keep a representative row.
    groups: Dict[tuple, dict] = {}
    for it in info:
        key = (it.get("category", "Other"), it.get("type", ""))
        g = groups.get(key)
        if g is None:
            groups[key] = {
                "category": it.get("category", "Other"),
                "type": it.get("type", ""),
                "message": it.get("message", ""),
                "details": it.get("details", ""),
                "url": it.get("url", ""),
                "count": 1,
            }
        else:
            g["count"] += 1

    rows_sorted = sorted(groups.values(), key=lambda g: (-g["count"], g["category"]))

    header = [
        Paragraph("<b>Category</b>", styles["cell_head"]),
        Paragraph("<b>Finding</b>", styles["cell_head"]),
        Paragraph("<b>Count</b>", styles["cell_head"]),
        Paragraph("<b>Recommended action</b>", styles["cell_head"]),
        Paragraph("<b>Example page</b>", styles["cell_head"]),
    ]
    data = [header]
    for g in rows_sorted:
        guidance = (INFO_GUIDANCE.get(g["type"]) or g["details"]
                    or "Review and address as a best-practice improvement.")
        data.append([
            Paragraph(esc(g["category"]), styles["cell"]),
            Paragraph(esc(g["message"]), styles["cell"]),
            Paragraph(esc(g["count"]), styles["cell"]),
            Paragraph(esc(guidance), styles["cell"]),
            Paragraph(esc(g["url"]), styles["url"]),
        ])
    table = Table(data, colWidths=[24 * mm, 52 * mm, 14 * mm, 60 * mm, 30 * mm],
                  repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_HEADER_BG),
        ("GRID", (0, 0), (-1, -1), 0.4, COLOR_LINE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_ZEBRA]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (2, 0), (2, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(table)
    return story


def _pages_appendix(report: dict, styles) -> List:
    pages = report.get("pages", [])
    if not pages:
        return []
    story: List = [PageBreak(), Paragraph("Appendix: Crawled Pages", styles["h2"]),
                   HRFlowable(width="100%", color=COLOR_LINE, spaceAfter=8)]
    header = [Paragraph("<b>URL</b>", styles["cell_head"]),
              Paragraph("<b>Status</b>", styles["cell_head"]),
              Paragraph("<b>Depth</b>", styles["cell_head"]),
              Paragraph("<b>Load (ms)</b>", styles["cell_head"])]
    data = [header]
    for page in pages[:MAX_PAGES_IN_PDF]:
        data.append([
            Paragraph(esc(page.get("url", "")), styles["url"]),
            Paragraph(esc(page.get("status", "")), styles["cell"]),
            Paragraph(esc(page.get("depth", "")), styles["cell"]),
            Paragraph(esc(page.get("load_time_ms", "")), styles["cell"]),
        ])
    table = Table(data, colWidths=[120 * mm, 20 * mm, 18 * mm, 22 * mm], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_HEADER_BG),
        ("GRID", (0, 0), (-1, -1), 0.4, COLOR_LINE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_ZEBRA]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(table)
    return story


def _simple_table_style() -> TableStyle:
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_HEADER_BG),
        ("GRID", (0, 0), (-1, -1), 0.5, COLOR_LINE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_ZEBRA]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ])


def _footer(canvas, doc) -> None:
    """Draw a page number and disclaimer on every page."""
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(COLOR_MUTED)
    canvas.drawString(15 * mm, 10 * mm,
                      "Auditor - automated compliance report (not legal advice)")
    canvas.drawRightString(195 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def build_pdf_report(report: dict) -> bytes:
    """Build the PDF and return its bytes."""
    risk = report.get("risk") or {}
    styles = _styles()

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=15 * mm, rightMargin=15 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title="Compliance Risk Audit",
        author="Auditor",
    )

    story: List = []
    story += _cover(report, risk, styles)
    story += _summary(report, risk, styles)
    story += _category_ranking(report, styles)
    story += _detailed_findings(report, styles)
    story += _informational_findings(report, styles)
    story += _pages_appendix(report, styles)

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()
