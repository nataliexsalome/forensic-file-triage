import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

SIGNATURES = {
    b"\x25\x50\x44\x46": [".pdf"],
    b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a": [".png"],
    b"\xff\xd8\xff": [".jpg", ".jpeg"],
    b"\x50\x4b\x03\x04": [".zip", ".docx", ".xlsx"],
    b"\x4d\x5a": [".exe", ".dll"],
}


def sha256_file(file_path: Path) -> str:
    hasher = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def detect_signature(file_path: Path) -> str:
    with file_path.open("rb") as f:
        header = f.read(16)
    for sig in SIGNATURES:
        if header.startswith(sig):
            return sig.hex()
    return "unknown"


def check_extension_mismatch(file_path: Path) -> bool:
    ext = file_path.suffix.lower()
    with file_path.open("rb") as f:
        header = f.read(16)
    for sig, allowed_exts in SIGNATURES.items():
        if header.startswith(sig):
            return ext not in allowed_exts
    return False


def scan_directory(target_dir: Path) -> list[dict]:
    records = []
    for path in sorted(target_dir.rglob("*")):
        if path.is_file():
            stat = path.stat()
            records.append(
                {
                    "file": str(path),
                    "size_bytes": stat.st_size,
                    "modified_utc": datetime.fromtimestamp(
                        stat.st_mtime, tz=timezone.utc
                    ).isoformat(),
                    "sha256": sha256_file(path),
                    "header_hex": detect_signature(path),
                    "extension_mismatch": check_extension_mismatch(path),
                }
            )
    return records


def verify_against_baseline(target_dir: Path, baseline_path: Path) -> None:
    baseline_records = json.loads(baseline_path.read_text(encoding="utf-8"))
    baseline_map = {item["file"]: item["sha256"] for item in baseline_records}
    current_files = {str(p): sha256_file(p) for p in sorted(target_dir.rglob("*")) if p.is_file()}

    for file_str, old_hash in baseline_map.items():
        if file_str not in current_files:
            print(f"[MISSING]   {file_str}")
        elif current_files[file_str] != old_hash:
            print(f"[MODIFIED]  {file_str} (SHA-256 changed!)")
        else:
            print(f"[UNCHANGED] {file_str}")

    for file_str in current_files:
        if file_str not in baseline_map:
            print(f"[NEW]       {file_str}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Basic Digital Forensics File Integrity & Header Checker"
    )
    parser.add_argument("target", help="Path to evidence directory to scan")
    parser.add_argument(
        "--out",
        default="triage_report.json",
        help="Output JSON report path (default: triage_report.json)",
    )
    parser.add_argument(
        "--verify",
        metavar="BASELINE_JSON",
        help="Verify current files against a saved baseline JSON report",
    )
    args = parser.parse_args()

    target_dir = Path(args.target)
    if not target_dir.exists() or not target_dir.is_dir():
        raise SystemExit(f"Target directory not found: {target_dir}")

    if args.verify:
        baseline_path = Path(args.verify)
        if not baseline_path.exists():
            raise SystemExit(f"Baseline file not found: {baseline_path}")
        verify_against_baseline(target_dir, baseline_path)
        return

    results = scan_directory(target_dir)
    out_path = Path(args.out)
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Scanned {len(results)} files. Report saved to {out_path}")


if __name__ == "__main__":
    main()