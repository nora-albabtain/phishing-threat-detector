"""REST API for the detector.

Run:  uvicorn app.api:app --reload      then open http://localhost:8000/docs
"""
from dataclasses import asdict
from functools import lru_cache

from fastapi import FastAPI, File, UploadFile
from pydantic import BaseModel, Field

from detector.attachments import analyze_attachment
from detector.model import URLDetector

MAX_UPLOAD_BYTES = 10 * 1024 * 1024

app = FastAPI(
    title="Phishing & Identity Threat Detector",
    description="Scores URLs with a machine learning model and analyzes attachments with static rules.",
    version="1.0.0",
)


class URLRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=2048, examples=["http://verify-account-mybank.xyz/login"])


@lru_cache
def get_detector() -> URLDetector:
    return URLDetector()


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/scan/url")
def scan_url(request: URLRequest) -> dict:
    return asdict(get_detector().predict(request.url))


@app.post("/scan/attachment")
async def scan_attachment(file: UploadFile = File(...)) -> dict:  # noqa: B008
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    report = analyze_attachment(file.filename or "unknown", content[:MAX_UPLOAD_BYTES])
    return asdict(report)
