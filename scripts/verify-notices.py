#!/usr/bin/env python3
"""Fail when the static binary's material module set and notices diverge."""

from __future__ import annotations

from pathlib import Path
import os
import re
import shutil
import subprocess
import sys

EXPECTED = {
    "github.com/dustin/go-humanize": "v1.0.1",
    "github.com/google/uuid": "v1.6.0",
    "github.com/remyoudompheng/bigfft": "v0.0.0-20230129092748-24d4a6f8daec",
    "go.yaml.in/yaml/v3": "v3.0.4",
    "golang.org/x/sys": "v0.46.0",
    "modernc.org/libc": "v1.74.1",
    "modernc.org/mathutil": "v1.7.1",
    "modernc.org/memory": "v1.11.0",
    "modernc.org/sqlite": "v1.54.0",
}
REQUIRED_NOTICE_MARKERS = {
    "Go standard library 1.26.5",
    "Apache License 2.0 full text",
    "Upstream LICENSE-3RD-PARTY.md",
    "Bundled Mersenne implementation LICENSE",
    "Bundled mmap-go material LICENSE",
    "SQLite public-domain statement",
    "https://www.spamhaus.org/drop/terms/",
    "aggregate `license=unknown`",
}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify-notices.py <static-binary>", file=sys.stderr)
        return 2
    binary = Path(sys.argv[1])
    if not binary.is_file():
        print("binary not found", file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parents[1]
    go_binary = os.environ.get("GO") or shutil.which("go")
    if not go_binary:
        local_go = root / ".tools" / "go" / "bin" / "go"
        if local_go.is_file():
            go_binary = str(local_go)
    if not go_binary:
        print("Go toolchain not found (set GO or install go)", file=sys.stderr)
        return 2
    output = subprocess.run((go_binary, "version", "-m", str(binary)), check=True, text=True, capture_output=True).stdout
    material: dict[str, str] = {}
    for line in output.splitlines():
        match = re.match(r"\s*dep\s+(\S+)\s+(\S+)", line)
        if match:
            material[match.group(1)] = match.group(2)
    if material != EXPECTED:
        print(f"material module inventory changed: {material!r}", file=sys.stderr)
        return 1
    notices = (root / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    missing = [f"{module} {version}" for module, version in EXPECTED.items() if module not in notices or version.lstrip("v") not in notices]
    missing.extend(marker for marker in REQUIRED_NOTICE_MARKERS if marker not in notices)
    if missing:
        print("third-party notices are incomplete: " + ", ".join(sorted(missing)), file=sys.stderr)
        return 1
    for graph_only in ("github.com/mattn/go-isatty", "github.com/ncruces/go-strftime"):
        if graph_only in material:
            print("graph-only assumption changed: " + graph_only, file=sys.stderr)
            return 1
    print("third-party notice inventory passed: 9 material modules plus Go/runtime bundled notices")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
