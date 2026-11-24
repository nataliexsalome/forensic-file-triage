# Forensic File Integrity & Header Triage Tool- NATALIE SALOME

A Python command-line utility for initial digital forensics file triage, SHA-256 cryptographic hashing, and post-acquisition integrity verification.

## Author & Provenance
- **Author:** Natalie Salome
- **Project Tier:** Digital Forensics & Incident Response (DFIR) Portfolio — Project 1 
- **Date Created:** 24th November 2026
- **Repository:** `forensic-file-triage`

## Features
- **Baseline Evidence Triage:** Recursively scans a target directory and records file paths, byte sizes, UTC last-modified timestamps, SHA-256 hashes, file header magic bytes (`hex`), and extension-vs-header mismatch flags.
- **Tamper & Integrity Verification (`--verify`):** Re-scans a directory and compares current file SHA-256 hashes against a saved baseline JSON report, flagging `[UNCHANGED]`, `[MODIFIED]`, `[NEW]`, and `[MISSING]` files.

## Requirements
- **Python 3.11+** (uses Python standard library modules only: `argparse`, `hashlib`, `json`, `datetime`, `pathlib`).

## Usage

### 1. Generate a Baseline Integrity Report
```bash
python triage.py sample_evidence --out triage_report.json

### 2. Verify Evidence Integrity After Changes
```bash
python triage.py sample_evidence --verify triage_report.json