"""Static, rule-based risk analysis of email attachments.

Nothing is executed: the file is only inspected (name, extension, first bytes,
and, for Office files, the list of entries inside the archive).
"""
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe",
    ".wsf", ".hta", ".ps1", ".msi", ".jar", ".lnk", ".iso", ".img", ".cpl",
}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}
SAFE_LOOKING_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"}
OFFICE_ZIP_EXTENSIONS = {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}

# File signatures ("magic bytes")
SIGNATURES = {
    b"MZ": "Windows executable",
    b"%PDF": "PDF document",
    b"PK\x03\x04": "ZIP / Office Open XML",
    b"\xd0\xcf\x11\xe0": "Legacy Office (OLE) document",
}

RTL_OVERRIDE = chr(0x202E)  # right-to-left override character


@dataclass
class AttachmentReport:
    filename: str
    risk_score: int = 0
    verdict: str = "low"
    findings: list[str] = field(default_factory=list)

    def add(self, points: int, finding: str) -> None:
        self.risk_score += points
        self.findings.append(finding)


def _detect_type(head: bytes) -> str | None:
    for sig, name in SIGNATURES.items():
        if head.startswith(sig):
            return name
    return None


def analyze_attachment(filename: str, content: bytes) -> AttachmentReport:
    """Score how risky an attachment is, with a list of reasons."""
    report = AttachmentReport(filename=filename)
    name = filename.lower()
    suffixes = [s.lower() for s in Path(name).suffixes]
    ext = suffixes[-1] if suffixes else ""

    if RTL_OVERRIDE in filename:
        report.add(60, "File name contains a hidden right-to-left override character to disguise its extension")
    if ext in EXECUTABLE_EXTENSIONS:
        report.add(60, f"Executable or script file type ({ext})")
    if len(suffixes) >= 2 and suffixes[-2] in SAFE_LOOKING_EXTENSIONS and ext in EXECUTABLE_EXTENSIONS:
        report.add(30, f"Double extension ({''.join(suffixes[-2:])}) pretends to be a harmless document")
    if ext in MACRO_EXTENSIONS:
        report.add(35, f"Macro-enabled Office file ({ext})")

    detected = _detect_type(content[:8])
    if detected == "Windows executable" and ext not in EXECUTABLE_EXTENSIONS:
        report.add(50, "Content is a Windows executable but the extension says otherwise")
    if detected == "PDF document" and ext not in {".pdf"}:
        report.add(15, "Content is a PDF but the extension does not match")

    if ext in OFFICE_ZIP_EXTENSIONS and detected == "ZIP / Office Open XML":
        try:
            import io
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                names = [n.lower() for n in zf.namelist()]
            if any(n.endswith("vbaproject.bin") for n in names):
                report.add(40, "Document contains embedded VBA macros")
            if any("externallink" in n or "oleobject" in n for n in names):
                report.add(20, "Document contains external links or embedded objects")
        except zipfile.BadZipFile:
            report.add(20, "Office file is corrupted or malformed")

    if ext == ".pdf" and detected == "PDF document":
        lowered = content.lower()
        if b"/javascript" in lowered or b"/js" in lowered:
            report.add(35, "PDF contains embedded JavaScript")
        if b"/launch" in lowered:
            report.add(35, "PDF contains a Launch action that can run programs")

    report.risk_score = min(report.risk_score, 100)
    if report.risk_score >= 60:
        report.verdict = "high"
    elif report.risk_score >= 30:
        report.verdict = "medium"
    if not report.findings:
        report.findings.append("No warning signs found")
    return report
