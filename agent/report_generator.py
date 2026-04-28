"""
SOC Incident Report — PDF Generator
Produces a clean, structured PDF from a structured report dictionary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

# ──────────────────────────────────────────────────────────────────────────────
# Types
# ──────────────────────────────────────────────────────────────────────────────

Colour = tuple[float, float, float]  # (R, G, B) in 0-1 range

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

PAGE_WIDTH  = 595
PAGE_HEIGHT = 842

MARGIN_LEFT   = 50
MARGIN_RIGHT  = 50
MARGIN_TOP    = 80   # increased — room for persistent header bar
MARGIN_BOTTOM = 60   # increased — room for persistent footer bar

LINE_HEIGHT       = 14
LINE_HEIGHT_LARGE = 28

CHARS_PER_LINE      = 90
LABEL_COLUMN_OFFSET = 160

# BUG FIX: the original code used U+2022 BULLET which is outside latin-1 and
# silently became '?' when the stream was encoded with errors="replace".
# U+00B7 MIDDLE DOT (0xB7) is identical in latin-1 and encodes cleanly.
BULLET = "\xb7"

DISCLAIMER = (
    "This report is automatically generated and must be validated by a SOC analyst."
)

# ── colour palette ────────────────────────────────────────────────────────────

BLACK      : Colour = (0.00, 0.00, 0.00)
WHITE      : Colour = (1.00, 1.00, 1.00)
GREY_LABEL : Colour = (0.40, 0.40, 0.40)
BRAND_DARK : Colour = (0.05, 0.15, 0.40)   # deep navy
BRAND_MID  : Colour = (0.20, 0.40, 0.70)   # medium blue
BRAND_LIGHT: Colour = (0.88, 0.92, 0.97)   # pale blue — shaded boxes / rows
RULE_LIGHT : Colour = (0.80, 0.84, 0.90)   # subtle row separators
PAGE_NUM_C : Colour = (0.70, 0.80, 0.95)   # page number text on dark header

SEVERITY_COLOURS: dict[str, Colour] = {
    "critical": (0.70, 0.10, 0.10),
    "high":     (0.85, 0.35, 0.05),
    "medium":   (0.80, 0.60, 0.00),
    "low":      (0.10, 0.50, 0.20),
    "unknown":  (0.35, 0.35, 0.35),
}

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _escape(text: str) -> str:
    return (
        str(text)
        .replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )

def _safe(value: Any, default: str = "--") -> str:
    return str(value) if value not in (None, "", "-", "*") else default

def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default

def _severity_colour(severity: str) -> Colour:
    return SEVERITY_COLOURS.get(severity.lower(), SEVERITY_COLOURS["unknown"])

# ──────────────────────────────────────────────────────────────────────────────
# Low-level PDF builder
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class _PDFBuilder:
    _pages       : list[list[str]] = field(default_factory=list)
    _current_page: list[str]       = field(default_factory=list)
    _page_number : int             = field(default=1)
    current_y    : int             = PAGE_HEIGHT - MARGIN_TOP

    # ── cursor ───────────────────────────────────────────────────────────────

    def _advance(self, amount: int) -> None:
        self.current_y -= amount

    def _ensure_space(self, needed: int) -> None:
        if self.current_y < MARGIN_BOTTOM + needed:
            self._new_page()

    def _new_page(self) -> None:
        if self._current_page:
            self._pages.append(self._current_page)
        self._current_page = []
        self._page_number += 1
        self.current_y = PAGE_HEIGHT - MARGIN_TOP

    # ── stream primitives ────────────────────────────────────────────────────

    @staticmethod
    def _text_op(text: str, x: float, y: float, size: int, colour: Colour) -> str:
        r, g, b = colour
        return (
            f"BT /F1 {size} Tf {x:.1f} {y:.1f} Td "
            f"{r:.3f} {g:.3f} {b:.3f} rg ({_escape(text)}) Tj ET"
        )

    @staticmethod
    def _rect_op(x: float, y: float, w: float, h: float, colour: Colour) -> str:
        r, g, b = colour
        return f"{r:.3f} {g:.3f} {b:.3f} rg {x:.1f} {y:.1f} {w:.1f} {h:.1f} re f"

    @staticmethod
    def _line_op(
        x1: float, y1: float, x2: float, y2: float,
        colour: Colour, width: float = 0.5,
    ) -> str:
        r, g, b = colour
        return (
            f"{width:.2f} w {r:.3f} {g:.3f} {b:.3f} RG "
            f"{x1:.1f} {y1:.1f} m {x2:.1f} {y2:.1f} l S"
        )

    def _emit(self, op: str) -> None:
        self._current_page.append(op)

    # ── public API ───────────────────────────────────────────────────────────

    def draw_text(
        self, text: str, x: float, size: int,
        colour: Colour = BLACK, advance: bool = True,
    ) -> None:
        self._emit(self._text_op(text, x, self.current_y, size, colour))
        if advance:
            self._advance(LINE_HEIGHT)

    def draw_rect(
        self, x: float, y: float, w: float, h: float,
        colour: Colour = BRAND_LIGHT,
    ) -> None:
        self._emit(self._rect_op(x, y, w, h, colour))

    def draw_line(
        self, x1: float, y1: float, x2: float, y2: float,
        colour: Colour = BLACK, width: float = 0.5,
    ) -> None:
        self._emit(self._line_op(x1, y1, x2, y2, colour, width))

    # ── serialisation ────────────────────────────────────────────────────────

    def build(self, path: Path, total_pages: int) -> None:
        if self._current_page:
            self._pages.append(self._current_page)

        objects: list[str] = []

        def add_obj(content: str) -> int:
            objects.append(content)
            return len(objects)

        font_id = add_obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        page_ids: list[int] = []
        content_ids: list[int] = []

        for page_idx, page in enumerate(self._pages, 1):
            ops = list(page)

            # persistent top bar
            br, bg, bb = BRAND_DARK
            ops.insert(0, f"{br:.3f} {bg:.3f} {bb:.3f} rg 0 {PAGE_HEIGHT-50:.1f} {PAGE_WIDTH:.1f} 50 re f")
            ops.insert(1, self._text_op("SOC INCIDENT REPORT", 50, PAGE_HEIGHT - 22, 9, WHITE))
            ops.insert(2, self._text_op(f"Page {page_idx} of {total_pages}", PAGE_WIDTH - 100, PAGE_HEIGHT - 22, 8, PAGE_NUM_C))

            # persistent bottom bar
            footer_y = MARGIN_BOTTOM - 20
            ops.append(self._line_op(MARGIN_LEFT, footer_y + 12, PAGE_WIDTH - MARGIN_RIGHT, footer_y + 12, BRAND_DARK, 0.5))
            ops.append(self._text_op(DISCLAIMER, MARGIN_LEFT, footer_y, 7, GREY_LABEL))

            stream = "\n".join(ops)
            enc_len = len(stream.encode("latin-1", "replace"))
            content_id = add_obj(f"<< /Length {enc_len} >>\nstream\n{stream}\nendstream")
            content_ids.append(content_id)
            page_ids.append(add_obj(""))

        kids = " ".join(f"{p} 0 R" for p in page_ids)
        pages_id = add_obj(f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>")

        for i, pid in enumerate(page_ids):
            objects[pid - 1] = (
                "<< /Type /Page "
                f"/Parent {pages_id} 0 R "
                "/MediaBox [0 0 595 842] "
                f"/Resources << /Font << /F1 {font_id} 0 R >> >> "
                f"/Contents {content_ids[i]} 0 R >>"
            )

        catalog_id = add_obj(f"<< /Type /Catalog /Pages {pages_id} 0 R >>")

        parts: list[str] = ["%PDF-1.4\n"]
        offsets: list[int] = [0]
        for i, obj in enumerate(objects, 1):
            offsets.append(sum(len(p.encode("latin-1", "replace")) for p in parts))
            parts.append(f"{i} 0 obj\n{obj}\nendobj\n")

        xref_offset = sum(len(p.encode("latin-1", "replace")) for p in parts)
        parts.append(f"xref\n0 {len(objects) + 1}\n")
        parts.append("0000000000 65535 f \n")
        for off in offsets[1:]:
            parts.append(f"{off:010d} 00000 n \n")
        parts.append(
            f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF"
        )

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes("".join(parts).encode("latin-1", "replace"))


# ──────────────────────────────────────────────────────────────────────────────
# High-level report renderer
# ──────────────────────────────────────────────────────────────────────────────

class ReportRenderer:

    def __init__(self) -> None:
        self._pdf = _PDFBuilder()

    # ── headings ─────────────────────────────────────────────────────────────

    def add_heading1(self, text: str) -> None:
        self._pdf._ensure_space(60)
        band_h = 40
        self._pdf.draw_rect(0, self._pdf.current_y - band_h + 24, PAGE_WIDTH, band_h, BRAND_DARK)
        self._pdf.draw_text(text, MARGIN_LEFT, 20, WHITE)
        self._pdf._advance(20)

    def add_heading2(self, text: str) -> None:
        self._pdf._ensure_space(50)
        self._pdf._advance(12)
        self._pdf.draw_text(text, MARGIN_LEFT, 13, BRAND_MID)
        rule_y = self._pdf.current_y + 2
        self._pdf.draw_line(MARGIN_LEFT, rule_y, PAGE_WIDTH - MARGIN_RIGHT, rule_y, BRAND_MID, 0.8)
        self._pdf._advance(8)

    # ── body text ─────────────────────────────────────────────────────────────

    def add_paragraph(self, text: str, size: int = 10) -> None:
        self._pdf._ensure_space(40)
        safe_text = _escape(_safe(text, "No information provided"))
        line_buffer = ""
        for word in safe_text.split():
            if len(line_buffer) + len(word) > CHARS_PER_LINE:
                self._pdf.draw_text(line_buffer, MARGIN_LEFT, size)
                self._pdf._ensure_space(20)
                line_buffer = word
            else:
                line_buffer += (" " if line_buffer else "") + word
        if line_buffer:
            self._pdf.draw_text(line_buffer, MARGIN_LEFT, size)
        self._pdf._advance(6)

    # ── structured elements ───────────────────────────────────────────────────

    def add_key_value(self, label: str, value: Any) -> None:
        self._pdf._ensure_space(20)
        self._pdf._emit(self._pdf._text_op(_escape(_safe(label, "N/A")), MARGIN_LEFT, self._pdf.current_y, 9, GREY_LABEL))
        self._pdf._emit(self._pdf._text_op(_escape(_safe(value, "Unknown")), MARGIN_LEFT + LABEL_COLUMN_OFFSET, self._pdf.current_y, 9, BLACK))
        self._pdf._advance(LINE_HEIGHT)

    def add_metadata_block(self, pairs: list[tuple[str, str]]) -> None:
        """Lightly shaded box containing key-value pairs."""
        self._pdf._ensure_space(len(pairs) * LINE_HEIGHT + 24)
        box_top = self._pdf.current_y + 8
        box_h   = len(pairs) * LINE_HEIGHT + 14
        self._pdf.draw_rect(MARGIN_LEFT, box_top - box_h, PAGE_WIDTH - MARGIN_LEFT - MARGIN_RIGHT, box_h, BRAND_LIGHT)
        self._pdf.draw_line(MARGIN_LEFT, box_top, PAGE_WIDTH - MARGIN_RIGHT, box_top, BRAND_MID, 0.4)
        self._pdf.draw_line(MARGIN_LEFT, box_top - box_h, PAGE_WIDTH - MARGIN_RIGHT, box_top - box_h, BRAND_MID, 0.4)
        self._pdf._advance(8)
        for label, value in pairs:
            self._pdf._emit(self._pdf._text_op(_escape(label), MARGIN_LEFT + 8, self._pdf.current_y, 9, GREY_LABEL))
            self._pdf._emit(self._pdf._text_op(_escape(value), MARGIN_LEFT + 8 + LABEL_COLUMN_OFFSET, self._pdf.current_y, 9, BLACK))
            self._pdf._advance(LINE_HEIGHT)
        self._pdf._advance(10)

    def add_severity_badge(self, severity: str) -> None:
        self._pdf._ensure_space(30)
        colour  = _severity_colour(severity)
        label   = f"  Severity: {severity.upper()}  "
        badge_w = len(label) * 5.8
        self._pdf.draw_rect(MARGIN_LEFT, self._pdf.current_y - 4, badge_w, 17, colour)
        self._pdf._emit(self._pdf._text_op(_escape(label), MARGIN_LEFT, self._pdf.current_y + 2, 9, WHITE))
        self._pdf._advance(24)

    def add_list(self, items: list[str] | None) -> None:
        """
        Bullet list.  Uses MIDDLE DOT (\\xb7) — a latin-1 safe character —
        instead of the original BULLET (U+2022) which produced '?' after
        latin-1 encoding with errors='replace'.
        """
        for item in items or ["No data available"]:
            self._pdf._ensure_space(20)
            self._pdf._emit(self._pdf._text_op(BULLET, MARGIN_LEFT + 4, self._pdf.current_y, 12, BRAND_MID))
            self._pdf._emit(self._pdf._text_op(_escape(_safe(item, "N/A")), MARGIN_LEFT + 18, self._pdf.current_y, 9, BLACK))
            self._pdf._advance(LINE_HEIGHT)
        self._pdf._advance(6)

    def add_table(self, headers: list[str], rows: list[list[Any]]) -> None:
        self._pdf._ensure_space(80)
        usable = PAGE_WIDTH - MARGIN_LEFT - MARGIN_RIGHT
        col_w  = usable // len(headers)

        # header row
        self._pdf.draw_rect(MARGIN_LEFT, self._pdf.current_y - 4, usable, LINE_HEIGHT + 6, BRAND_DARK)
        for ci, hdr in enumerate(headers):
            self._pdf._emit(self._pdf._text_op(_escape(hdr), MARGIN_LEFT + ci * col_w + 4, self._pdf.current_y, 9, WHITE))
        self._pdf._advance(LINE_HEIGHT + 8)

        # data rows
        for ri, row in enumerate(rows):
            self._pdf._ensure_space(30)
            if ri % 2 == 0:
                self._pdf.draw_rect(MARGIN_LEFT, self._pdf.current_y - 3, usable, LINE_HEIGHT + 2, BRAND_LIGHT)
            for ci, cell in enumerate(row):
                self._pdf._emit(self._pdf._text_op(_escape(_safe(str(cell), "N/A")), MARGIN_LEFT + ci * col_w + 4, self._pdf.current_y, 8, BLACK))
            self._pdf._advance(LINE_HEIGHT)
            self._pdf.draw_line(MARGIN_LEFT, self._pdf.current_y + 2, PAGE_WIDTH - MARGIN_RIGHT, self._pdf.current_y + 2, RULE_LIGHT, 0.3)
        self._pdf._advance(12)

    # ── spacing ───────────────────────────────────────────────────────────────

    def add_section_break(self) -> None:
        self._pdf._advance(LINE_HEIGHT_LARGE)

    # ── finalisation ─────────────────────────────────────────────────────────

    def save(self, path: Path) -> Path:
        total = len(self._pdf._pages) + (1 if self._pdf._current_page else 0)
        self._pdf.build(path, total)
        return path


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────

def generate_incident_report(report: dict, output_path: Path) -> Path:
    """
    Render *report* as a PDF and write it to *output_path*.

    Parameters
    ----------
    report:
        Dictionary with the following keys (all optional — missing values
        are replaced with sensible defaults):

        - ``title``              (str)
        - ``severity``           (str)
        - ``confidence``         (float | str)  0-1 scale
        - ``explanation``        (str)
        - ``iocs``               (list[dict])   each: ``type``, ``value``, ``context``
        - ``attack_sequence``    (list[str])
        - ``mitre_technique_id`` (str)
        - ``mitre_tactic``       (str)
        - ``remediation_steps``  (list[dict])   each: ``priority``, ``action``

    output_path:
        Destination ``.pdf`` file.  Parent directories are created
        automatically.

    Returns
    -------
    Path
        The resolved *output_path* after the file has been written.
    """
    renderer   = ReportRenderer()
    severity   = _safe(report.get("severity"), "unknown")
    confidence = _safe_float(report.get("confidence"))

    # cover / metadata
    renderer.add_heading1(_safe(report.get("title"), "Untitled Incident"))
    renderer.add_severity_badge(severity)
    renderer.add_metadata_block([
        ("Generated",  datetime.now().strftime("%Y-%m-%d %H:%M")),
        ("Confidence", f"{confidence:.0%}"),
        ("Severity",   severity.upper()),
    ])
    renderer.add_section_break()

    # narrative
    renderer.add_heading2("Executive Summary")
    renderer.add_paragraph(report.get("explanation"))

    # indicators of compromise
    iocs: list[dict] = report.get("iocs") or []
    renderer.add_heading2("Indicators of Compromise")
    renderer.add_list([f"{i.get('type', 'N/A')}: {i.get('value', 'N/A')}" for i in iocs])

    if iocs:
        renderer.add_heading2("IoC Details")
        renderer.add_table(
            headers=["Type", "Value", "Context"],
            rows=[[i.get("type"), i.get("value"), i.get("context")] for i in iocs],
        )
    renderer.add_section_break()

    # attack timeline & MITRE
    renderer.add_heading2("Attack Timeline")
    renderer.add_list(report.get("attack_sequence"))

    renderer.add_heading2("MITRE ATT&CK Context")
    renderer.add_metadata_block([
        ("Technique ID", _safe(report.get("mitre_technique_id"))),
        ("Tactic",       _safe(report.get("mitre_tactic"))),
    ])
    renderer.add_section_break()

    # remediation
    renderer.add_heading2("Remediation Steps")
    steps: list[dict] = report.get("remediation_steps") or []
    renderer.add_list([f"[{s.get('priority', 'N/A')}] {s.get('action', 'N/A')}" for s in steps])

    return renderer.save(output_path)