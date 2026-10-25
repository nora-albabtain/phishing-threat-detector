"""Command-line interface.

Examples:
    python -m detector.cli train --data data/sample_urls.csv
    python -m detector.cli url "http://verify-account-mybank.xyz/login"
    python -m detector.cli file suspicious_invoice.pdf.exe
"""
import argparse
import json
from dataclasses import asdict
from pathlib import Path

from detector.attachments import analyze_attachment
from detector.model import DEFAULT_MODEL_PATH, URLDetector, train


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="detector", description="Phishing & identity threat detector")
    sub = parser.add_subparsers(dest="command", required=True)

    p_train = sub.add_parser("train", help="Train the URL model on a CSV (columns: url,label)")
    p_train.add_argument("--data", default="data/sample_urls.csv")
    p_train.add_argument("--model", default=str(DEFAULT_MODEL_PATH))

    p_url = sub.add_parser("url", help="Scan a URL")
    p_url.add_argument("url")
    p_url.add_argument("--model", default=str(DEFAULT_MODEL_PATH))

    p_file = sub.add_parser("file", help="Scan an attachment (static analysis, nothing is executed)")
    p_file.add_argument("path")

    args = parser.parse_args(argv)
    if args.command == "train":
        print(json.dumps(train(args.data, args.model), indent=2))
    elif args.command == "url":
        print(json.dumps(asdict(URLDetector(args.model).predict(args.url)), indent=2, ensure_ascii=False))
    elif args.command == "file":
        path = Path(args.path)
        report = analyze_attachment(path.name, path.read_bytes())
        print(json.dumps(asdict(report), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
