from fastapi.testclient import TestClient

from app import api
from data.generate_sample import main as generate
from detector.model import URLDetector, train


def test_api_endpoints(tmp_path):
    csv_path = tmp_path / "urls.csv"
    generate(n_per_class=200, out=str(csv_path))
    model_path = tmp_path / "model.joblib"
    train(csv_path, model_path)

    api.get_detector.cache_clear()
    original = api.get_detector
    api.get_detector = lambda: URLDetector(model_path)
    try:
        client = TestClient(api.app)
        assert client.get("/health").json() == {"status": "ok"}

        r = client.post("/scan/url", json={"url": "http://verify-account-mybank.xyz/login"})
        assert r.status_code == 200
        assert r.json()["verdict"] in {"phishing", "suspicious"}

        r = client.post("/scan/attachment", files={"file": ("invoice.pdf.exe", b"MZ\x90\x00")})
        assert r.status_code == 200
        assert r.json()["verdict"] == "high"
    finally:
        api.get_detector = original
