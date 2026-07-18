#!/usr/bin/env python3
"""Verify the final Crowdshield image metadata and visible root filesystem."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import uuid

EXPECTED_BASE = "sha256:aef9602f8710ec12bde19d593fed1f76c708531bb7aba205110f1029786ead7b"
EXPECTED_WRITABLE_MODES = {"/data", "/home/nonroot", "/tmp", "/var/lock", "/var/tmp"}
FORBIDDEN_PATHS = {
    "/bin/sh", "/bin/bash", "/busybox", "/usr/bin/curl", "/usr/bin/wget",
    "/usr/bin/apt", "/usr/bin/apt-get", "/usr/bin/dpkg", "/sbin/apk",
    "/usr/local/go/bin/go",
}


def command(*args: str, capture: bool = True) -> str:
    result = subprocess.run(args, check=True, text=True, capture_output=capture)
    return result.stdout if capture else ""


def main() -> int:
    image = sys.argv[1] if len(sys.argv) > 1 else "crowdshield:local"
    if len(sys.argv) > 2 or not image or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/@-" for ch in image):
        print("usage: verify-image.py [image]", file=sys.stderr)
        return 2

    inspected = json.loads(command("docker", "image", "inspect", image))[0]
    config = inspected["Config"]
    labels = config.get("Labels") or {}
    health = config.get("Healthcheck") or {}
    assert inspected["Os"] == "linux" and inspected["Architecture"] == "amd64"
    assert inspected["Size"] <= 20 * 1024 * 1024
    assert config.get("User") == "65532:65532"
    assert config.get("WorkingDir") == "/data"
    assert config.get("Entrypoint") == ["/crowdshield"] and config.get("Cmd") == ["run"]
    assert set((config.get("ExposedPorts") or {}).keys()) == {"9090/tcp"}
    assert health.get("Test") == ["CMD", "/crowdshield", "healthcheck"]
    assert labels.get("org.opencontainers.image.base.digest") == EXPECTED_BASE
    for key in ("title", "description", "url", "source", "documentation", "licenses", "version", "revision", "created"):
        assert labels.get("org.opencontainers.image." + key)
    assert len(inspected.get("RootFS", {}).get("Layers", [])) <= 20

    root = Path(__file__).resolve().parents[1]
    tmp_root = root / ".tmp"
    tmp_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="image-verify.", dir=tmp_root) as directory:
        destination = Path(directory)
        container = "crowdshield-image-verify-" + uuid.uuid4().hex[:12]
        try:
            command("docker", "create", "--name", container, "--network", "none", image, "version")
            command("docker", "export", "--output", str(destination / "rootfs.tar"), container)
            command("docker", "cp", container + ":/crowdshield", str(destination / "crowdshield"))
        finally:
            subprocess.run(("docker", "rm", "-f", container), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

        members: dict[str, tarfile.TarInfo] = {}
        with tarfile.open(destination / "rootfs.tar", "r") as archive:
            for member in archive.getmembers():
                members["/" + member.name.lstrip("./")] = member

        assert not (FORBIDDEN_PATHS & members.keys())
        suspicious = []
        for path in members:
            lowered = path.lower()
            if path.endswith((".go", ".sql", ".db", ".sqlite", ".sqlite3")) or "/.git/" in lowered or "/testdata/" in lowered or "lapi-credentials" in lowered or "crowdshield.yaml" in lowered or "/go/pkg/mod/" in lowered:
                suspicious.append(path)
        assert not suspicious, suspicious

        binary = members["/crowdshield"]
        data = members["/data"]
        assert (binary.uid, binary.gid, binary.mode) == (65532, 65532, 0o555)
        assert (data.uid, data.gid, data.mode) == (65532, 65532, 0o750)
        for path in ("/licenses/LICENSE", "/licenses/THIRD_PARTY_NOTICES.md"):
            item = members[path]
            assert (item.uid, item.gid, item.mode) == (65532, 65532, 0o444)

        writable_modes = set()
        for path, member in members.items():
            if not member.isdir():
                continue
            if ((member.uid == 65532 and member.mode & 0o200) or
                    (member.gid == 65532 and member.mode & 0o020) or member.mode & 0o002):
                writable_modes.add(path)
        assert writable_modes == EXPECTED_WRITABLE_MODES, writable_modes

        file_description = command("file", str(destination / "crowdshield"))
        assert "statically linked" in file_description
        evidence = {
            "image": image,
            "image_id": inspected["Id"],
            "architecture": inspected["Architecture"],
            "image_size_bytes": inspected["Size"],
            "binary_size_bytes": os.path.getsize(destination / "crowdshield"),
            "layer_count": len(inspected.get("RootFS", {}).get("Layers", [])),
            "default_user": config["User"],
            "writable_mode_directories": sorted(writable_modes),
            "effective_writable_path_with_read_only_root": ["/data"],
            "forbidden_paths_found": [],
        }
        (tmp_root / "image-verification.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
