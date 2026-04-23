"""
Professional SOC Incident Report PDF generator
Clean layout, human-like formatting, no noisy placeholders
"""

from datetime import datetime
from pathlib import Path


# ─────────────────────────────────────────────
# 🛠 UTILS
# ─────────────────────────────────────────────

def _escape_pdf_text(text: str) -> str:
    if not text:
        return ""
    return (
        str(text)
        .replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )


def _safe(value, default="--"):
    """Standardized fallback for missing values."""
    return value if value not in [None, "", "-", "*"] else default


# ─────────────────────────────────────────────
# 📄 PDF GENERATOR
# ─────────────────────────────────────────────

class PDFGenerator:
    def __init__(self, title="SOC Incident Report"):
        self.title = title
        self.pages = []
        self.current_page = []

        self.page_width = 595
        self.page_height = 842

        self.margin_left = 50
        self.margin_right = 50
        self.margin_top = 60
        self.margin_bottom = 50

        self.current_y = self.page_height - self.margin_top

        self.line = 14
        self.line_big = 28

    # ─────────────────────────────
    # TEXT ELEMENTS
    # ─────────────────────────────

    def add_heading1(self, text):
        if self.current_y < self.margin_bottom + 60:
            self._new_page()

        self.current_page.append(
            f"BT /F1 26 Tf {self.margin_left} {self.current_y} Td "
            f"0.05 0.15 0.4 rg ({_escape_pdf_text(text)}) Tj ET"
        )
        self.current_y -= 40

    def add_heading2(self, text):
        if self.current_y < self.margin_bottom + 40:
            self._new_page()

        self.current_y -= 10
        self.current_page.append(
            f"BT /F1 14 Tf {self.margin_left} {self.current_y} Td "
            f"0.2 0.4 0.7 rg ({_escape_pdf_text(text)}) Tj ET"
        )
        self.current_y -= 20

    def add_paragraph(self, text, size=10):
        if self.current_y < self.margin_bottom + 40:
            self._new_page()

        text = _escape_pdf_text(_safe(text, "No information provided"))
        words = text.split()
        line = ""

        for word in words:
            if len(line) + len(word) > 90:
                self._draw(line, size)
                line = word
            else:
                line += (" " if line else "") + word

        if line:
            self._draw(line, size)

        self.current_y -= 6

    def _draw(self, text, size):
        self.current_page.append(
            f"BT /F1 {size} Tf {self.margin_left} {self.current_y} Td "
            f"0 0 0 rg ({text}) Tj ET"
        )
        self.current_y -= self.line

    # ─────────────────────────────
    # STRUCTURED BLOCKS
    # ─────────────────────────────

    def add_key_value(self, label, value):
        if self.current_y < self.margin_bottom + 20:
            self._new_page()

        label = _escape_pdf_text(_safe(label, "N/A"))
        value = _escape_pdf_text(_safe(value, "Unknown"))

        self.current_page.append(
            f"BT /F1 9 Tf {self.margin_left} {self.current_y} Td "
            f"0.4 0.4 0.4 rg ({label}) Tj ET"
        )

        self.current_page.append(
            f"BT /F1 9 Tf {self.margin_left + 160} {self.current_y} Td "
            f"0 0 0 rg ({value}) Tj ET"
        )

        self.current_y -= self.line

    def add_list(self, items):
        items = items or ["No data available"]

        for item in items:
            if self.current_y < self.margin_bottom + 20:
                self._new_page()

            item = _escape_pdf_text(_safe(item, "N/A"))

            self.current_page.append(
                f"BT /F1 9 Tf {self.margin_left} {self.current_y} Td (•) Tj ET"
            )
            self.current_page.append(
                f"BT /F1 9 Tf {self.margin_left + 15} {self.current_y} Td "
                f"({item}) Tj ET"
            )

            self.current_y -= self.line

        self.current_y -= 6

    def add_table(self, headers, rows):
        if self.current_y < self.margin_bottom + 80:
            self._new_page()

        col_width = (self.page_width - self.margin_left - self.margin_right) // len(headers)

        # headers
        for i, h in enumerate(headers):
            x = self.margin_left + i * col_width
            self.current_page.append(
                f"BT /F1 9 Tf {x} {self.current_y} Td "
                f"0.1 0.2 0.6 rg ({_escape_pdf_text(h)}) Tj ET"
            )

        self.current_y -= self.line

        # rows
        for row in rows:
            if self.current_y < self.margin_bottom + 30:
                self._new_page()

            for i, cell in enumerate(row):
                x = self.margin_left + i * col_width
                cell = _escape_pdf_text(_safe(str(cell), "N/A"))

                self.current_page.append(
                    f"BT /F1 8 Tf {x} {self.current_y} Td "
                    f"({cell}) Tj ET"
                )

            self.current_y -= self.line

        self.current_y -= 10

    # ─────────────────────────────
    # PAGE CONTROL
    # ─────────────────────────────

    def add_section_space(self):
        self.current_y -= self.line_big

    def _new_page(self):
        if self.current_page:
            self.pages.append(self.current_page)

        self.current_page = []
        self.current_y = self.page_height - self.margin_top

    # ─────────────────────────────
    # PDF BUILD
    # ─────────────────────────────

    def generate_pdf(self, path: Path):
        if self.current_page:
            self.pages.append(self.current_page)

        objects = []

        def add_obj(content):
            objects.append(content)
            return len(objects)

        font_id = add_obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

        page_ids = []
        content_ids = []

        for page in self.pages:
            stream = "\n".join(page)

            content_id = add_obj(
                f"<< /Length {len(stream.encode('latin-1','replace'))} >>\n"
                f"stream\n{stream}\nendstream"
            )

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

        pdf = ["%PDF-1.4\n"]
        offsets = [0]

        for i, obj in enumerate(objects, 1):
            offsets.append(sum(len(p.encode("latin-1","replace")) for p in pdf))
            pdf.append(f"{i} 0 obj\n{obj}\nendobj\n")

        xref = sum(len(p.encode("latin-1","replace")) for p in pdf)

        pdf.append(f"xref\n0 {len(objects)+1}\n")
        pdf.append("0000000000 65535 f \n")

        for off in offsets[1:]:
            pdf.append(f"{off:010d} 00000 n \n")

        pdf.append(
            "trailer\n"
            f"<< /Size {len(objects)+1} /Root {catalog_id} 0 R >>\n"
            f"startxref\n{xref}\n%%EOF"
        )

        path.write_bytes("".join(pdf).encode("latin-1","replace"))


# ─────────────────────────────────────────────
# 🚀 REPORT GENERATOR
# ─────────────────────────────────────────────

def generate_incident_report(report: dict, output_path: Path):

    pdf = PDFGenerator()

    pdf.add_heading1("SOC INCIDENT REPORT")

    severity = _safe(report.get("severity", "unknown")).upper()
    pdf.add_heading2(f"Severity: {severity}")

    pdf.add_key_value("Generated", datetime.now().strftime("%Y-%m-%d %H:%M"))
    pdf.add_key_value("Title", report.get("title"))
    confidence = report.get("confidence", 0)
    try:
        confidence = float(confidence)
    except:
        confidence = 0.0

    pdf.add_key_value("Confidence", f"{confidence:.0%}")

    pdf.add_section_space()

    pdf.add_heading2("Executive Summary")
    pdf.add_paragraph(report.get("explanation"))

    pdf.add_heading2("Indicators of Compromise")
    iocs = report.get("iocs", [])
    pdf.add_list([f"{i.get('type','N/A')}: {i.get('value','N/A')}" for i in iocs])

    pdf.add_section_space()

    pdf.add_heading2("Attack Timeline")
    pdf.add_list(report.get("attack_sequence"))

    pdf.add_heading2("MITRE Context")
    pdf.add_key_value("Technique", report.get("mitre_technique_id"))
    pdf.add_key_value("Tactic", report.get("mitre_tactic"))

    if iocs:
        pdf.add_heading2("IoC Details")
        rows = [[i.get("type"), i.get("value"), i.get("context")] for i in iocs]
        pdf.add_table(["Type", "Value", "Context"], rows)

    pdf.add_section_space()

    pdf.add_heading2("Remediation")
    steps = report.get("remediation_steps", [])
    pdf.add_list([f"[{s.get('priority','N/A')}] {s.get('action','N/A')}" for s in steps])

    pdf.add_section_space()

    pdf.add_paragraph(
        "This report is automatically generated and must be validated by a SOC analyst.",
        size=8
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.generate_pdf(output_path)

    return output_path