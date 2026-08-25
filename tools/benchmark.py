#!/usr/bin/env python3
"""Measure Lockbox rather than making claims about it.

Run: `python3 tools/benchmark.py [--items 1000]`

Everything here is measured on the machine you run it on. The numbers in the
README are whatever this printed on the machine named there -- if your hardware
differs, run it again and trust your own output.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import resource
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from lockbox.core.kdf import benchmark as kdf_benchmark, default_params  # noqa: E402
from lockbox.core.model import Item  # noqa: E402
from lockbox.core.search import search  # noqa: E402
from lockbox.core.vault import Vault  # noqa: E402
from lockbox.tools.generators import generate_password  # noqa: E402

PASSWORD = b"benchmark master password"


def timed(fn, repeat=1):
    start = time.perf_counter()
    for _ in range(repeat):
        result = fn()
    return (time.perf_counter() - start) / repeat, result


def package_size():
    total = files = 0
    for path in SRC.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        total += path.stat().st_size
        files += 1
    return total, files


def source_lines():
    return sum(
        len(p.read_text(encoding="utf-8").splitlines())
        for p in SRC.rglob("*.py")
        if "__pycache__" not in p.parts
    )


def dependency_tree():
    """Direct plus transitive third-party packages actually imported."""
    code = (
        "import sys, importlib;"
        "[importlib.import_module(m) for m in ('cryptography.hazmat.primitives.ciphers.aead',)];"
        "roots={m.split('.')[0] for m in sys.modules};"
        "std=set(sys.stdlib_module_names);"
        "print(sorted(r for r in roots if r not in std and not r.startswith('_')))"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    return out.stdout.strip()


def import_time():
    code = "import time; t=time.perf_counter(); import lockbox.core.vault; " \
           "print(round((time.perf_counter()-t)*1000, 1))"
    env = dict(os.environ, PYTHONPATH=str(SRC))
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    return float(out.stdout.strip())


def cli_startup(args):
    env = dict(os.environ, PYTHONPATH=str(SRC))
    start = time.perf_counter()
    subprocess.run([sys.executable, "-m", "lockbox", *args], capture_output=True, env=env)
    return (time.perf_counter() - start) * 1000


def peak_rss_mb():
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def current_rss_mb():
    """Resident set right now (Linux). Peak includes Argon2's transient
    64 MiB buffer, which is released as soon as the key is derived."""
    try:
        with open("/proc/self/statm", encoding="ascii") as fh:
            pages = int(fh.read().split()[1])
        return pages * os.sysconf("SC_PAGE_SIZE") / (1024 * 1024)
    except (OSError, ValueError, IndexError):
        return float("nan")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--items", type=int, default=1000)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    results = {}
    size, files = package_size()
    results["package"] = {
        "source_bytes": size,
        "source_kib": round(size / 1024, 1),
        "python_files": files,
        "source_lines": source_lines(),
    }
    results["dependencies"] = {
        "direct": ["cryptography", "argon2-cffi"],
        "imported_third_party": dependency_tree(),
    }
    results["startup"] = {
        "core_import_ms": round(import_time(), 1),
        "cli_gen_ms": round(cli_startup(["gen", "--quiet"]), 1),
        "cli_help_ms": round(cli_startup(["--help"]), 1),
    }

    kdf = default_params()
    results["kdf"] = {
        "algorithm": kdf.algorithm,
        "params": kdf.params,
        "derive_seconds": round(kdf_benchmark(kdf), 3),
    }

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "bench.lbx")
        vault = Vault(path)
        create_time, _ = timed(lambda: vault.create(PASSWORD))

        items = [
            Item(title=f"Service {i}", username=f"user{i}@example.com",
                 password=generate_password(length=20).value,
                 url=f"https://service{i}.example.com", tags=["bench"],
                 notes="x" * 40)
            for i in range(args.items)
        ]
        vault.add_many(items)
        save_time, _ = timed(vault.save)
        file_size = os.path.getsize(path)
        vault.lock()

        reopened = Vault(path)
        unlock_time, _ = timed(lambda: reopened.unlock(PASSWORD))
        search_time, hits = timed(lambda: search(reopened.items(), "service 999"), repeat=20)
        fuzzy_time, _ = timed(lambda: search(reopened.items(), "srvc"), repeat=20)
        filter_time, _ = timed(lambda: search(reopened.items(), "tag:bench"), repeat=20)
        integrity_time, report = timed(reopened.integrity_check)

        from lockbox.core.audit import audit

        audit_time, _ = timed(lambda: audit(reopened.items(), reopened.settings))

        results["vault"] = {
            "items": args.items,
            "file_bytes": file_size,
            "file_kib": round(file_size / 1024, 1),
            "bytes_per_item": round(file_size / args.items, 1),
            "create_seconds": round(create_time, 3),
            "save_seconds": round(save_time, 4),
            "unlock_seconds": round(unlock_time, 3),
            "integrity_seconds": round(integrity_time, 4),
            "integrity_ok": report["ok"],
        }
        results["operations_ms"] = {
            "search_exact": round(search_time * 1000, 3),
            "search_fuzzy": round(fuzzy_time * 1000, 3),
            "search_filter": round(filter_time * 1000, 3),
            "security_audit": round(audit_time * 1000, 1),
            "generate_password": round(timed(lambda: generate_password(length=20), 200)[0] * 1000, 3),
        }
        reopened.lock()

    from lockbox.tools import TOOLS
    from lockbox.tools.otp import totp
    from lockbox.tools.qr import encode as qr_encode

    results["tools"] = {
        "count": len(TOOLS),
        "totp_ms": round(timed(lambda: totp("JBSWY3DPEHPK3PXP"), 500)[0] * 1000, 4),
        "qr_encode_ms": round(timed(lambda: qr_encode("otpauth://totp/x?secret=JBSWY3DP"), 20)[0] * 1000, 2),
    }
    results["memory"] = {
        "resident_mb_with_vault_open": round(current_rss_mb(), 1),
        "peak_rss_mb": round(peak_rss_mb(), 1),
        "note": f"resident figure holds {args.items} decrypted items; the peak "
                "includes Argon2's transient 64 MiB buffer",
    }

    if args.json:
        print(json.dumps(results, indent=2))
        return 0

    def section(title, data, unit=""):
        print(f"\n{title}")
        for key, value in data.items():
            print(f"  {key:<28} {value}{unit}")

    print("Lockbox benchmark")
    print(f"python {sys.version.split()[0]} on {sys.platform}")
    for name, data in results.items():
        section(name, data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
