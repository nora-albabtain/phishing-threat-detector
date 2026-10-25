import io
import zipfile

import pytest

from data.generate_sample import main as generate
from detector.attachments import analyze_attachment
from detector.features import FEATURE_NAMES, explain, extract_features
from detector.model import URLDetector, train


# ---------- URL features ----------
def test_feature_vector_length():
    assert len(extract_features("https://github.com")) == len(FEATURE_NAMES)


def test_ip_and_at_symbol_detected():
    f = dict(zip(FEATURE_NAMES, extract_features("http://192.168.1.10/login@evil")))
    assert f["has_ip_address"] == 1
    assert f["has_at_symbol"] == 1
    assert f["uses_https"] == 0


def test_explain_lists_reasons():
    reasons = explain("http://verify-account-mybank.xyz/login")
    assert any("phishing" in r.lower() for r in reasons)
    assert any("top-level domain" in r for r in reasons)


def test_scheme_is_optional():
    assert extract_features("github.com") == extract_features("http://github.com")


# ---------- Model ----------
@pytest.fixture(scope="module")
def detector(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("model")
    csv_path = tmp / "urls.csv"
    generate(n_per_class=300, out=str(csv_path))
    model_path = tmp / "model.joblib"
    metrics = train(csv_path, model_path)
    assert metrics["f1"] > 0.9
    return URLDetector(model_path)


def test_flags_phishing_url(detector):
    result = detector.predict("http://secure-login-mybank-verify.xyz/account/update.php?token=12345")
    assert result.verdict in {"phishing", "suspicious"}
    assert result.reasons


def test_trusts_legit_url(detector):
    assert detector.predict("https://www.wikipedia.org/about").verdict == "safe"


# ---------- Attachments ----------
def test_double_extension_executable_is_high_risk():
    report = analyze_attachment("invoice.pdf.exe", b"MZ\x90\x00")
    assert report.verdict == "high"
    assert any("Double extension" in f for f in report.findings)


def test_disguised_executable_is_flagged():
    report = analyze_attachment("photo.jpg", b"MZ\x90\x00")
    assert any("executable" in f.lower() for f in report.findings)


def test_macro_document_detected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/document.xml", "<doc/>")
        zf.writestr("word/vbaProject.bin", b"\x00")
    report = analyze_attachment("report.docm", buf.getvalue())
    assert report.verdict == "high"
    assert any("VBA macros" in f for f in report.findings)


def test_clean_pdf_is_low_risk():
    report = analyze_attachment("notes.pdf", b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj")
    assert report.verdict == "low"


def test_pdf_javascript_flagged():
    report = analyze_attachment("form.pdf", b"%PDF-1.7\n<< /JavaScript (app.alert(1)) >>")
    assert report.risk_score >= 30


def test_rtl_override_trick():
    report = analyze_attachment("invoice" + chr(0x202E) + "fdp.exe", b"MZ")
    assert any("right-to-left" in f for f in report.findings)
