"""Portable client PDFs with local saved screenshots, never remote images."""

from io import BytesIO
import os
from pathlib import Path
import threading
from xml.sax.saxutils import escape

from .capture_images import has_capture_image
from .report_exports import display_date


_FONT_LOCK = threading.Lock()
_MAX_IMAGE_BYTES = 25 * 1024 * 1024


def capture_image_bytes(data_dir, capture, *, project_id, domain, scheme):
    """Accept only this project's validated PNG/JPEG beneath its run folder."""
    if (not data_dir or not has_capture_image(capture) or capture.get("project_id") != project_id
            or capture.get("domain") != domain or capture.get("scheme") != scheme):
        return None
    try:
        runs = Path(data_dir).resolve() / "runs"
        run = runs / capture["run_id"]
        if runs.is_symlink() or run.is_symlink():
            return None
        path = run
        for part in Path(capture["relative_path"]).parts:
            path /= part
            if path.is_symlink():
                return None
        path = path.resolve(strict=True)
        if not path.is_relative_to(run.resolve(strict=True)) or not path.is_file():
            return None
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            if os.fstat(stream.fileno()).st_size > _MAX_IMAGE_BYTES:
                return None
            data = stream.read(_MAX_IMAGE_BYTES + 1)
        if len(data) > _MAX_IMAGE_BYTES:
            return None
        suffix = path.suffix.lower()
        return data if (suffix == ".png" and data.startswith(b"\x89PNG\r\n\x1a\n")
                        or suffix in {".jpg", ".jpeg"} and data.startswith(b"\xff\xd8\xff")) else None
    except (OSError, ValueError, RuntimeError):
        return None


def _fonts():
    import reportlab
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    with _FONT_LOCK:
        if not {"ClientReport", "ClientReport-Bold"}.issubset(pdfmetrics.getRegisteredFontNames()):
            candidates = [Path("/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf"),
                          Path("/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf")]
            regular = next((path for path in candidates if path.is_file() and path.with_name("LiberationSans-Bold.ttf").is_file()),
                           Path(reportlab.__file__).parent / "fonts" / "Vera.ttf")
            bold = regular.with_name("VeraBd.ttf" if regular.name == "Vera.ttf" else "LiberationSans-Bold.ttf")
            pdfmetrics.registerFont(TTFont("ClientReport", str(regular)))
            pdfmetrics.registerFont(TTFont("ClientReport-Bold", str(bold)))
            pdfmetrics.registerFontFamily("ClientReport", normal="ClientReport", bold="ClientReport-Bold")


class _Document:
    def __init__(self, project, scope):
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.pdfgen.canvas import Canvas
        _fonts()
        self.colors = colors
        self.buffer = BytesIO()
        self.width, self.height = A4
        self.margin, self.bottom = 45, 43
        self.content_width = self.width - 2 * self.margin
        self.project, self.scope, self.domain = project, scope, ""
        self.canvas = Canvas(self.buffer, pagesize=A4, pageCompression=1)
        self.canvas.setTitle(project["name"] + " - Domain monitoring report")
        self.canvas.setAuthor("Domain monitoring")
        self.body = ParagraphStyle("Body", fontName="ClientReport", fontSize=9.5, leading=13,
                                   textColor=colors.HexColor("#243b33"), splitLongWords=True)
        self.title = ParagraphStyle("Domain", parent=self.body, fontName="ClientReport-Bold", fontSize=17, leading=22)
        self.label = ParagraphStyle("Label", parent=self.body, fontName="ClientReport-Bold", fontSize=11, leading=15,
                                    textColor=colors.HexColor("#246454"))
        self.caption = ParagraphStyle("Caption", parent=self.body, fontSize=8, leading=11,
                                      textColor=colors.HexColor("#617168"))
        self._header()

    def _header(self, *, continued=False):
        from reportlab.pdfbase.pdfmetrics import stringWidth
        self.canvas.setFont("ClientReport-Bold", 10)
        title = self.project["name"]
        while title and stringWidth(title, "ClientReport-Bold", 10) > self.content_width:
            title = title[:-4] + "..."
        self.canvas.setFillColor(self.colors.HexColor("#246454"))
        self.canvas.drawString(self.margin, self.height - 29, title)
        self.canvas.setStrokeColor(self.colors.HexColor("#dce6df"))
        self.canvas.line(self.margin, self.height - 37, self.width - self.margin, self.height - 37)
        self.y = self.height - 52
        if continued and self.domain:
            self.text(self.domain + " (continued)", self.caption, gap=6)

    def _footer(self):
        self.canvas.setFillColor(self.colors.HexColor("#617168"))
        self.canvas.setFont("ClientReport", 8)
        self.canvas.drawString(self.margin, 23, "Domain monitoring report")
        self.canvas.drawRightString(self.width - self.margin, 23, f"Page {self.canvas.getPageNumber()}")

    def page(self, *, continued=True):
        self._footer()
        self.canvas.showPage()
        self._header(continued=continued)

    def ensure(self, height):
        if self.y - height < self.bottom:
            self.page()

    def paragraph(self, value, style=None):
        from reportlab.platypus import Paragraph
        text = "".join(char for char in str(value or "") if ord(char) >= 32 or char in "\n\t")
        return Paragraph(escape(text).replace("\n", "<br/>"), style or self.body)

    def text(self, value, style=None, *, gap=6):
        pending = [self.paragraph(value, style)]
        while pending:
            paragraph = pending.pop(0)
            _, height = paragraph.wrap(self.content_width, self.y - self.bottom)
            if height > self.y - self.bottom:
                pieces = paragraph.split(self.content_width, max(0, self.y - self.bottom))
                if not pieces:
                    self.page()
                    pending.insert(0, paragraph)
                    continue
                first, pending = pieces[0], pieces[1:] + pending
                _, height = first.wrap(self.content_width, self.y - self.bottom)
                first.drawOn(self.canvas, self.margin, self.y - height)
                self.y -= height
                self.page()
            else:
                paragraph.drawOn(self.canvas, self.margin, self.y - height)
                self.y -= height + gap

    def protocol(self, domain, scheme, endpoint, data_dir):
        from PIL import Image, UnidentifiedImageError
        from reportlab.lib.utils import ImageReader
        image = endpoint.get("image")
        data = capture_image_bytes(data_dir, image, project_id=self.project["id"], domain=domain, scheme=scheme)
        reader, image_width, image_height = None, 0, 0
        if data:
            try:
                with Image.open(BytesIO(data)) as check:
                    width, height = check.size
                    if check.format not in {"PNG", "JPEG"} or width * height > 40_000_000 or not width or not height:
                        raise ValueError("Unsupported image dimensions")
                    check.verify()
                reader = ImageReader(BytesIO(data))
                reader.getRGBData()  # Decode before drawing so a bad image can be labelled unavailable.
                scale = min(self.content_width / width, 225 / height)
                image_width, image_height = width * scale, height * scale
            except (OSError, ValueError, UnidentifiedImageError, Image.DecompressionBombError):
                reader = None
        title = endpoint["title"] + " - " + endpoint["status"]
        _, title_height = self.paragraph(title).wrap(self.content_width, 1000)
        _, url_height = self.paragraph(endpoint["url"], self.caption).wrap(self.content_width, 1000)
        self.ensure(min(title_height + url_height + image_height + 62, self.height - 100))
        self.text(scheme.upper(), self.label, gap=3)
        self.text(title, gap=3)
        if endpoint.get("previous_title") and endpoint["previous_title"] != endpoint["title"]:
            self.text("Previous title: " + endpoint["previous_title"], self.caption, gap=3)
        self.text(endpoint["url"], self.caption, gap=7)
        if reader:
            self.ensure(image_height + 25)
            self.canvas.drawImage(reader, self.margin + (self.content_width - image_width) / 2,
                                  self.y - image_height, width=image_width, height=image_height, mask="auto")
            self.y -= image_height + 5
            label = "Previous capture: " if endpoint.get("previous_image") else "Captured "
            self.text(label + display_date(image.get("captured_at")), self.caption, gap=11)
        elif endpoint.get("shared_with"):
            self.text("HTML matches " + endpoint["shared_with"].upper() + "; a separate screenshot was not taken.", self.caption)
        else:
            self.text("Saved screenshot file unavailable." if image else "No screenshot saved for this observation.", self.caption)

    def finish(self):
        self._footer()
        self.canvas.save()
        self.buffer.seek(0)
        return self.buffer


def client_pdf(project, records, *, data_dir, scope, scan=None):
    """One vertical HTTP/HTTPS screenshot column; compact notes stay together."""
    records = list(records)
    document = _Document(project, scope)
    document.text(project["name"], document.title)
    document.text("Domain monitoring report", document.label)
    document.text(scope, document.body)
    if scan:
        status = {"partial": "Completed with gaps", "completed": "Completed"}.get(scan.get("status"), scan.get("status", ""))
        document.text("Scan started " + display_date(scan.get("started_at")) + " - " + status, document.caption)
    document.text(f"{len(records)} matching domains. HTTP and HTTPS are separate observations, shown together.", document.caption, gap=14)
    with_images = [row for row in records if any(endpoint.get("image") for endpoint in row["endpoints"].values())]
    imaged_domains = {row["domain"] for row in with_images}
    notes_only = [row for row in records if row["domain"] not in imaged_domains]
    if not records:
        document.text("No findings match this export view.")
    for index, row in enumerate(with_images):
        if index:
            document.page(continued=False)
        document.domain = row["domain"]
        document.text(row["domain"], document.title)
        if row["sources"]:
            document.text("Generated from: " + "; ".join(row["sources"]), document.caption)
        document.text("; ".join(row["findings"]) or "Saved website observations")
        document.text("DNS: " + row["dns_status"] + (" - " + row["dns_now"] if row["dns_now"] else ""), document.caption)
        if row["dns_before"]:
            document.text("Previous DNS: " + row["dns_before"], document.caption)
        for scheme in ("http", "https"):
            if scheme in row["endpoints"]:
                document.protocol(row["domain"], scheme, row["endpoints"][scheme], data_dir)
        if row["notes"]:
            document.text("\n".join(row["notes"]), document.caption)
    if notes_only:
        if with_images:
            document.page(continued=False)
        document.domain = ""
        document.text("DNS and other observations", document.label, gap=12)
        for row in notes_only:
            document.ensure(90)
            document.domain = row["domain"]
            document.text(row["domain"], document.label, gap=4)
            if row["sources"]:
                document.text("Generated from: " + "; ".join(row["sources"]), document.caption, gap=3)
            document.text("; ".join(row["findings"]) or "Saved domain observation", gap=3)
            document.text("DNS: " + row["dns_status"] + (" - " + row["dns_now"] if row["dns_now"] else ""), document.caption)
            if row["dns_before"]:
                document.text("Previous DNS: " + row["dns_before"], document.caption)
            for scheme in ("http", "https"):
                endpoint = row["endpoints"].get(scheme)
                if endpoint:
                    document.text(f"{scheme.upper()}: {endpoint['title']} - {endpoint['status']}", document.caption, gap=3)
                    if endpoint.get("previous_title") and endpoint["previous_title"] != endpoint["title"]:
                        document.text("Previous title: " + endpoint["previous_title"], document.caption, gap=3)
                    if endpoint["url"]:
                        document.text(endpoint["url"], document.caption, gap=3)
            if row["notes"]:
                document.text("\n".join(row["notes"]), document.caption)
            document.y -= 9
    return document.finish()
