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
# Constants
# ──────────────────────────────────────────────────────────────────────────────

PAGE_WIDTH = 595
PAGE_HEIGHT = 842

MARGIN_LEFT = 50
MARGIN_RIGHT = 50
MARGIN_TOP = 60
MARGIN_BOTTOM = 50

LINE_HEIGHT = 14
LINE_HEIGHT_LARGE = 28

CHARS_PER_LINE = 90
LABEL_COLUMN_OFFSET = 160

DISCLAIMER = (
    "This report is automatically generated and must be validated by a SOC analyst."
)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _escape(text: str) -> str:
    """Escape characters that are special in PDF string literals."""
    return (
        str(text)
        .replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )


def _safe(value: Any, default: str = "--") -> str:
    """Return *value* as a string, or *default* when the value is empty/missing."""
    return str(value) if value not in (None, "", "-", "*") else default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


# ──────────────────────────────────────────────────────────────────────────────
# Low-level PDF builder
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class _PDFBuilder:
    """
    Minimal, dependency-free PDF-1.4 assembler.

    Manages pages, a cursor (*current_y*), and a list of raw PDF stream
    operators.  Call ``build(path)`` to serialise everything to disk.
    """

    _pages: list[list[str]] = field(default_factory=list)
    _current_page: list[str] = field(default_factory=list)
    current_y: int = PAGE_HEIGHT - MARGIN_TOP

    # ── cursor helpers ───────────────────────────────────────────────────────

    def _advance(self, amount: int) -> None:
        self.current_y -= amount

    def _ensure_space(self, needed: int) -> None:
        """Start a new page when there is not enough vertical space left."""
        if self.current_y < MARGIN_BOTTOM + needed:
            self._new_page()

    def _new_page(self) -> None:
        if self._current_page:
            self._pages.append(self._current_page)
        self._current_page = []
        self.current_y = PAGE_HEIGHT - MARGIN_TOP

    # ── primitive drawing ────────────────────────────────────────────────────

    def _text_op(
        self,
        text: str,
        x: int,
        y: int,
        size: int,
        r: float,
        g: float,
        b: float,
    ) -> str:
        return (
            f"BT /F1 {size} Tf {x} {y} Td "
            f"{r} {g} {b} rg ({_escape(text)}) Tj ET"
        )

    def _emit(self, op: str) -> None:
        self._current_page.append(op)

    # ── public drawing API ───────────────────────────────────────────────────

    def draw_text(
        self,
        text: str,
        x: int,
        size: int,
        r: float = 0.0,
        g: float = 0.0,
        b: float = 0.0,
    ) -> None:
        self._emit(self._text_op(text, x, self.current_y, size, r, g, b))
        self._advance(LINE_HEIGHT)

    # ── serialisation ────────────────────────────────────────────────────────

    def build(self, path: Path) -> None:
        """Write the PDF to *path*, creating parent directories as needed."""
        if self._current_page:
            self._pages.append(self._current_page)

        objects: list[str] = []

        def add_obj(content: str) -> int:
            objects.append(content)
            return len(objects)

        font_id = add_obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

        page_ids: list[int] = []
        content_ids: list[int] = []

        for page in self._pages:
            stream = "\n".join(page)
            encoded_len = len(stream.encode("latin-1", "replace"))
            content_id = add_obj(
                f"<< /Length {encoded_len} >>\nstream\n{stream}\nendstream"
            )
            content_ids.append(content_id)
            page_ids.append(add_obj(""))  # placeholder; filled in below

        kids = " ".join(f"{p} 0 R" for p in page_ids)
        pages_id = add_obj(
            f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>"
        )

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
            "trailer\n"
            f"<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF"
        )

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes("".join(parts).encode("latin-1", "replace"))


# ──────────────────────────────────────────────────────────────────────────────
# High-level report renderer
# ──────────────────────────────────────────────────────────────────────────────

class ReportRenderer:
    """
    Renders a structured SOC incident report onto a ``_PDFBuilder``.

    Each ``add_*`` method corresponds to a semantic document element
    (heading, paragraph, key-value row, list, table).  Page-overflow
    checks are centralised so individual methods stay focused on layout.
    """

    def __init__(self) -> None:
        self._pdf = _PDFBuilder()

    # ── headings ─────────────────────────────────────────────────────────────

    def add_heading1(self, text: str) -> None:
        self._pdf._ensure_space(60)
        self._pdf.draw_text(text, MARGIN_LEFT, size=26, r=0.05, g=0.15, b=0.4)
        self._pdf._advance(14)  # extra gap after H1

    def add_heading2(self, text: str) -> None:
        self._pdf._ensure_space(40)
        self._pdf._advance(10)  # pre-gap
        self._pdf.draw_text(text, MARGIN_LEFT, size=14, r=0.2, g=0.4, b=0.7)
        self._pdf._advance(6)   # post-gap

    # ── body text ─────────────────────────────────────────────────────────────

    def add_paragraph(self, text: str, size: int = 10) -> None:
        """Word-wrap *text* and emit one draw call per line."""
        self._pdf._ensure_space(40)
        safe_text = _escape(_safe(text, "No information provided"))

        line_buffer = ""
        for word in safe_text.split():
            if len(line_buffer) + len(word) > CHARS_PER_LINE:
                self._pdf.draw_text(line_buffer, MARGIN_LEFT, size=size)
                self._pdf._ensure_space(20)
                line_buffer = word
            else:
                line_buffer += (" " if line_buffer else "") + word

        if line_buffer:
            self._pdf.draw_text(line_buffer, MARGIN_LEFT, size=size)

        self._pdf._advance(6)

    # ── structured elements ───────────────────────────────────────────────────

    def add_key_value(self, label: str, value: Any) -> None:
        self._pdf._ensure_space(20)
        safe_label = _escape(_safe(label, "N/A"))
        safe_value = _escape(_safe(value, "Unknown"))

        self._pdf._emit(
            self._pdf._text_op(
                safe_label, MARGIN_LEFT, self._pdf.current_y,
                size=9, r=0.4, g=0.4, b=0.4,
            )
        )
        self._pdf._emit(
            self._pdf._text_op(
                safe_value, MARGIN_LEFT + LABEL_COLUMN_OFFSET, self._pdf.current_y,
                size=9, r=0.0, g=0.0, b=0.0,
            )
        )
        self._pdf._advance(LINE_HEIGHT)

    def add_list(self, items: list[str] | None) -> None:
        for item in items or ["No data available"]:
            self._pdf._ensure_space(20)
            safe_item = _escape(_safe(item, "N/A"))

            self._pdf._emit(
                self._pdf._text_op(
                    "•", MARGIN_LEFT, self._pdf.current_y,
                    size=9, r=0.0, g=0.0, b=0.0,
                )
            )
            self._pdf._emit(
                self._pdf._text_op(
                    safe_item, MARGIN_LEFT + 15, self._pdf.current_y,
                    size=9, r=0.0, g=0.0, b=0.0,
                )
            )
            self._pdf._advance(LINE_HEIGHT)

        self._pdf._advance(6)

    def add_table(self, headers: list[str], rows: list[list[Any]]) -> None:
        self._pdf._ensure_space(80)
        usable_width = PAGE_WIDTH - MARGIN_LEFT - MARGIN_RIGHT
        col_width = usable_width // len(headers)

        # Header row
        for col_idx, header in enumerate(headers):
            x = MARGIN_LEFT + col_idx * col_width
            self._pdf._emit(
                self._pdf._text_op(
                    _escape(header), x, self._pdf.current_y,
                    size=9, r=0.1, g=0.2, b=0.6,
                )
            )
        self._pdf._advance(LINE_HEIGHT)

        # Data rows
        for row in rows:
            self._pdf._ensure_space(30)
            for col_idx, cell in enumerate(row):
                x = MARGIN_LEFT + col_idx * col_width
                self._pdf._emit(
                    self._pdf._text_op(
                        _escape(_safe(str(cell), "N/A")), x, self._pdf.current_y,
                        size=8, r=0.0, g=0.0, b=0.0,
                    )
                )
            self._pdf._advance(LINE_HEIGHT)

        self._pdf._advance(10)

    # ── spacing ───────────────────────────────────────────────────────────────

    def add_section_break(self) -> None:
        self._pdf._advance(LINE_HEIGHT_LARGE)

    # ── finalisation ─────────────────────────────────────────────────────────

    def save(self, path: Path) -> Path:
        self._pdf.build(path)
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

        - ``title``            (str)
        - ``severity``         (str)
        - ``confidence``       (float | str)  0–1 scale
        - ``explanation``      (str)
        - ``iocs``             (list[dict])   each: ``type``, ``value``, ``context``
        - ``attack_sequence``  (list[str])
        - ``mitre_technique_id`` (str)
        - ``mitre_tactic``     (str)
        - ``remediation_steps`` (list[dict])  each: ``priority``, ``action``

    output_path:
        Destination ``.pdf`` file.  Parent directories are created
        automatically.

    Returns
    -------
    Path
        The resolved *output_path* after the file has been written.
    """
    renderer = ReportRenderer()

    # ── cover metadata ────────────────────────────────────────────────────────
    renderer.add_heading1("SOC INCIDENT REPORT")
    renderer.add_heading2(f"Severity: {_safe(report.get('severity'), 'UNKNOWN').upper()}")
    renderer.add_key_value("Generated", datetime.now().strftime("%Y-%m-%d %H:%M"))
    renderer.add_key_value("Title", report.get("title"))
    confidence = _safe_float(report.get("confidence"))
    renderer.add_key_value("Confidence", f"{confidence:.0%}")
    renderer.add_section_break()

    # ── narrative ─────────────────────────────────────────────────────────────
    renderer.add_heading2("Executive Summary")
    renderer.add_paragraph(report.get("explanation"))

    # ── indicators ───────────────────────────────────────────────────────────
    iocs: list[dict] = report.get("iocs") or []
    renderer.add_heading2("Indicators of Compromise")
    renderer.add_list(
        [f"{i.get('type', 'N/A')}: {i.get('value', 'N/A')}" for i in iocs]
    )
    renderer.add_section_break()

    # ── timeline & MITRE ─────────────────────────────────────────────────────
    renderer.add_heading2("Attack Timeline")
    renderer.add_list(report.get("attack_sequence"))

    renderer.add_heading2("MITRE Context")
    renderer.add_key_value("Technique", report.get("mitre_technique_id"))
    renderer.add_key_value("Tactic", report.get("mitre_tactic"))

    if iocs:
        renderer.add_heading2("IoC Details")
        renderer.add_table(
            headers=["Type", "Value", "Context"],
            rows=[[i.get("type"), i.get("value"), i.get("context")] for i in iocs],
        )

    renderer.add_section_break()

    # ── remediation ───────────────────────────────────────────────────────────
    renderer.add_heading2("Remediation")
    steps: list[dict] = report.get("remediation_steps") or []
    renderer.add_list(
        [f"[{s.get('priority', 'N/A')}] {s.get('action', 'N/A')}" for s in steps]
    )

    renderer.add_section_break()

    # ── footer disclaimer ─────────────────────────────────────────────────────
    renderer.add_paragraph(DISCLAIMER, size=8)

    return renderer.save(output_path)