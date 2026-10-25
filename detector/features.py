"""Turn a URL into numeric features a machine learning model can learn from.

Every feature is explainable, which makes the model easy to teach and to audit.
"""
import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlparse

SUSPICIOUS_WORDS = (
    "login", "signin", "verify", "account", "update", "secure", "banking",
    "confirm", "password", "wallet", "invoice", "suspend", "unlock", "billing",
)
SHORTENERS = ("bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly")
RISKY_TLDS = ("xyz", "top", "zip", "click", "country", "gq", "tk", "ml", "cf", "work", "rest", "support")

FEATURE_NAMES = [
    "url_length",
    "host_length",
    "path_length",
    "num_dots",
    "num_hyphens",
    "num_digits",
    "digit_ratio",
    "num_subdomains",
    "has_at_symbol",
    "has_ip_address",
    "uses_https",
    "suspicious_word_count",
    "is_shortener",
    "risky_tld",
    "has_double_slash_redirect",
    "query_param_count",
    "host_entropy",
    "has_punycode",
]


def _normalize(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def extract_features(url: str) -> list[float]:
    """Return the feature vector for one URL, in the order of FEATURE_NAMES."""
    full = _normalize(url)
    parsed = urlparse(full)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    lowered = full.lower()
    digits = sum(ch.isdigit() for ch in full)
    tld = host.rsplit(".", 1)[-1] if "." in host else ""

    return [
        len(full),
        len(host),
        len(path),
        full.count("."),
        full.count("-"),
        digits,
        digits / max(len(full), 1),
        max(host.count(".") - 1, 0),
        int("@" in full),
        int(_is_ip(host)),
        int(parsed.scheme == "https"),
        sum(lowered.count(word) for word in SUSPICIOUS_WORDS),
        int(any(host == s or host.endswith("." + s) for s in SHORTENERS)),
        int(tld in RISKY_TLDS),
        int("//" in full[len(parsed.scheme) + 3:]),
        len([p for p in parsed.query.split("&") if p]),
        _entropy(host),
        int("xn--" in host),
    ]


def explain(url: str) -> list[str]:
    """Human-readable warning signs found in a URL (used to explain predictions)."""
    f = dict(zip(FEATURE_NAMES, extract_features(url)))
    reasons = []
    if f["has_ip_address"]:
        reasons.append("Uses a raw IP address instead of a domain name")
    if f["has_at_symbol"]:
        reasons.append("Contains '@', which can hide the real destination")
    if f["suspicious_word_count"]:
        reasons.append("Contains words often used in phishing (login, verify, account...)")
    if f["is_shortener"]:
        reasons.append("Uses a URL shortener that hides the final destination")
    if f["risky_tld"]:
        reasons.append("Uses a top-level domain frequently abused for phishing")
    if f["num_subdomains"] >= 3:
        reasons.append("Has many subdomains, a common trick to imitate trusted sites")
    if f["has_punycode"]:
        reasons.append("Uses punycode, which can disguise look-alike characters")
    if not f["uses_https"]:
        reasons.append("Does not use HTTPS")
    if f["url_length"] > 75:
        reasons.append("Unusually long URL")
    if f["has_double_slash_redirect"]:
        reasons.append("Contains an embedded redirect ('//') in the path")
    return reasons
