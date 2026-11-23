"""Run tests and save a reproducible environment-specific log."""
import io
import platform
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path


def main():
    base = Path(__file__).resolve().parent
    log = io.StringIO()
    log.write("PhishWise v0.1.0 automated verification\n")
    log.write(f"Run time (UTC): {datetime.now(timezone.utc).isoformat()}\n")
    log.write(f"Platform: {platform.platform()}\nPython: {sys.version}\n")
    log.write("Synthetic developer tests; NOT an independent accuracy evaluation.\n\n")
    suite = unittest.defaultTestLoader.discover(str(base / "tests"))
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    evidence = base / "evidence"
    evidence.mkdir(exist_ok=True)
    # Each run creates a separate evidence file, retaining the earlier environment's results.
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination = evidence / f"test_run_{platform.system().lower()}_{stamp}.txt"
    destination.write_text(log.getvalue(), encoding="utf-8")
    print(log.getvalue())
    print(f"Saved test log: {destination}")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
