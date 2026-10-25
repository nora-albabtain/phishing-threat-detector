"""Generate a SYNTHETIC demo dataset of legitimate and phishing-style URLs.

The phishing examples are made up from common patterns (fake brand names, look-alike
hosts, IP addresses, risky TLDs). They are NOT real phishing links. Use this data to
learn and test the pipeline, then retrain on a real dataset (see README).

Usage:
    python data/generate_sample.py            # writes data/sample_urls.csv
"""
import csv
import random
from pathlib import Path

random.seed(7)

LEGIT_DOMAINS = [
    "wikipedia.org", "github.com", "python.org", "microsoft.com", "amazon.com", "google.com",
    "my.gov.sa", "moe.gov.sa", "tuwaiq.edu.sa", "coursera.org", "stackoverflow.com", "bbc.com",
    "aljazeera.net", "linkedin.com", "apple.com", "spa.gov.sa", "ksu.edu.sa", "pnu.edu.sa",
]
LEGIT_PATHS = [
    "", "/", "/about", "/en/news", "/docs/getting-started", "/products/laptops", "/search?q=python",
    "/careers", "/ar/services", "/blog/2026/ai-in-education", "/help/contact", "/courses/machine-learning",
]
FAKE_BRANDS = ["mybank", "shopnow", "paysafe-online", "cloudmail", "netstream", "fastpost", "govservice"]
RISKY_TLDS = ["xyz", "top", "click", "support", "work", "rest"]
PHISH_WORDS = ["login", "verify", "account", "secure", "update", "confirm", "unlock", "billing"]


def legit_url() -> str:
    scheme = "https" if random.random() < 0.95 else "http"
    sub = random.choice(["", "www.", "docs.", "en."])
    return f"{scheme}://{sub}{random.choice(LEGIT_DOMAINS)}{random.choice(LEGIT_PATHS)}"


def phishing_url() -> str:
    brand = random.choice(FAKE_BRANDS)
    word = random.choice(PHISH_WORDS)
    word2 = random.choice(PHISH_WORDS)
    tld = random.choice(RISKY_TLDS)
    pattern = random.randint(1, 6)
    if pattern == 1:  # brand hidden in a long chain of subdomains
        return f"http://{brand}.com.{word}-{word2}.{random.randint(10, 999)}.{tld}/{word}?id={random.randint(1000, 99999)}"
    if pattern == 2:  # raw IP address
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        return f"http://{ip}/{brand}/{word}.php?session={random.randint(10**6, 10**7)}"
    if pattern == 3:  # '@' trick
        return f"http://{brand}.com@{word}-{brand}.{tld}/{word2}"
    if pattern == 4:  # look-alike with digits replacing letters
        lookalike = brand.replace("o", "0").replace("a", "4").replace("i", "1")
        return f"https://{word}-{lookalike}.{tld}/{word2}/index.html"
    if pattern == 5:  # embedded redirect
        return f"http://{word}-{brand}.{tld}/redirect//{brand}.com/{word2}"
    return f"http://secure-{word}-{brand}-{word2}.{tld}/{word}/{word2}.php?user=&token={random.randint(10**5, 10**6)}"


def main(n_per_class: int = 600, out: str = "data/sample_urls.csv") -> None:
    rows = [(legit_url(), 0) for _ in range(n_per_class)] + [(phishing_url(), 1) for _ in range(n_per_class)]
    random.shuffle(rows)
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["url", "label"])
        writer.writerows(rows)
    print(f"Wrote {len(rows)} synthetic URLs to {out}")


if __name__ == "__main__":
    main()
