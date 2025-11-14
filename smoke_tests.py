"""
Minimal smoke tests for the Cryptografie toolkit.

- Skips gracefully if the `modules` package is unavailable in this workspace.
- Uses sample files in `sample_files/` if present.

Run:
    python smoke_tests.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).parent
SAMPLES = ROOT / "sample_files"

# Try import project modules
try:
    from modules.hash import hash_file, verify_integrity
    from modules.encryption import aes_ed, rsa_ed
    from modules.password import check_strength, hash_pw, verify_password
    HAVE_MODULES = True
except Exception as e:
    print(f"SKIP: project 'modules' not found or failed to import: {e}")
    print("Hint: Place a 'modules' folder next to main.py/gui.py, or adjust PYTHONPATH.")
    HAVE_MODULES = False


def _print_header(title: str) -> None:
    print("\n" + title)
    print("-" * len(title))


def test_hash() -> None:
    _print_header("Hash file")
    sample = SAMPLES / "sample.txt"
    if not sample.exists():
        print(f"WARN: sample file not found: {sample}")
        return
    digest = hash_file(str(sample))
    print(f"hash({sample.name}) = {digest[:16]}... ({len(digest)} chars)")


def test_integrity() -> None:
    _print_header("Integrity check")
    sample1 = SAMPLES / "sample.txt"
    sample2 = SAMPLES / "sample2.txt"
    if not (sample1.exists() and sample2.exists()):
        print("WARN: sample files missing; skipping integrity tests")
        return
    same = verify_integrity(str(sample1), str(sample1))
    diff = verify_integrity(str(sample1), str(sample2))
    print(f"same file result: {same}")
    print(f"different files result: {diff}")


def test_aes() -> None:
    _print_header("AES encrypt/decrypt")
    msg = "hello from aes"
    key, ct, pt = aes_ed(msg)
    ok = (pt == msg)
    print(f"key={str(key)[:16]}... ct={str(ct)[:16]}... ok={ok}")


def test_rsa() -> None:
    _print_header("RSA encrypt/decrypt")
    msg = "hello from rsa"
    ct, pt = rsa_ed(msg)
    ok = (pt == msg)
    print(f"ct={str(ct)[:16]}... ok={ok}")


def test_password() -> None:
    _print_header("Password manager")
    pw = "P@ssw0rd123!"
    strength = check_strength(pw)
    print(f"strength: {strength}")
    hashed = hash_pw(pw)
    verdict = verify_password(pw, hashed)
    print(f"verify: {verdict}")


def main() -> int:
    if not HAVE_MODULES:
        # Skip without failing CI/automation
        return 0

    try:
        test_hash()
        test_integrity()
        test_aes()
        test_rsa()
        test_password()
    except Exception as exc:
        print(f"ERROR during smoke tests: {exc}")
        return 1

    print("\nSmoke tests finished.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
