# Container and supply-chain security

This document explains the container-specific threat assumptions, build design, runtime restrictions, and remaining operator responsibilities. The application-level model is in [threat-model.md](threat-model.md).

## Runtime base selection

Three options were evaluated:

- **scratch** — smallest attack surface, but requires manually curating CA roots, numeric identity files, license metadata, and scanner hints.
- **distroless static nonroot** — maintained CA roots and identity metadata, multi-architecture manifests, useful package metadata for scanners, and no shell/package manager.
- **Alpine/minimal distro** — convenient debugging and package management, but a larger mutable runtime surface that Crowdshield does not need.

The image uses `gcr.io/distroless/static-debian12:nonroot` pinned by immutable manifest-list digest. It provides the strongest maintainability/CA/scanner combination while keeping the runtime shell-free. The Go binary is built with `CGO_ENABLED=0` and verified statically linked.

Distroless contains conventional mode-writable directories (`/home/nonroot`, `/tmp`, `/var/lock`, `/var/tmp`). Crowdshield neither uses nor mounts them, and Compose makes the entire root filesystem read-only. The only effective writable path in normal operation is the `/data` bind mount. A `/tmp` mount was intentionally not added because the bounded container smoke test demonstrates startup, health, SQLite operation, and shutdown without it.

## Immutable build inputs

The Dockerfile pins:

- Dockerfile frontend `docker/dockerfile:1.19.0` by digest;
- Go builder `golang:1.26.5-bookworm` by digest;
- distroless runtime by digest.

The build context is deny-by-default and admits only module manifests, production Go/migration source, project license, and third-party notices. It excludes Git metadata, config, credentials, `data/`, caches, tools, tests, fixtures, reports, local binaries, databases, and documentation not required by the image.

The production binary uses `-mod=readonly`, `-trimpath`, `-buildvcs=false`, empty Go build ID, stripped symbols, and linker-provided version/revision/UTC build date. Build arguments are validated before interpolation. Build caches do not enter final layers.

The final image contains the executable, `/data`, project/runtime notices, and pinned distroless files only. CI/rootfs inspection rejects source, migrations as standalone files, test fixtures, credentials, config, state, shell, download clients, package managers, and Go toolchains.

## Runtime identity and filesystem

- Dockerfile default user: numeric `65532:65532`.
- Compose user: explicit numeric `CROWDSHIELD_UID:GID` for host bind compatibility.
- Root filesystem: read-only.
- Writable mount: `/data` only.
- Config and credentials: separate read-only bind mounts.
- Credential contract: regular non-symlink `0600`, matching runtime owner.
- Working directory: `/data`.
- No mutable application/config data is baked into the image.

Numeric identities avoid dependence on host usernames and NSS. The operator remains responsible for matching host ownership and for protecting Docker daemon access, which can bypass container filesystem controls.

## Process restrictions

Compose applies:

- `cap_drop: [ALL]`;
- `no-new-privileges:true`;
- `pids_limit: 128`;
- no privileged mode;
- no devices;
- no host PID, IPC, user, or network namespace;
- no Docker socket;
- no `init: true` helper.

The Go executable is PID 1 and directly handles SIGINT/SIGTERM. It does not spawn worker processes, so an init shim would add a binary without solving a demonstrated need. Docker's default seccomp/AppArmor/SELinux policy remains in force; deployments with established custom profiles may tighten it further after testing.

CPU and memory limits are not guessed in the portable baseline because feed sizes and homelab capacity differ. Operators should add deployment-specific limits and observe dry-run/full-sync peaks before enforcing them. The fixed download/response/database/history/PID bounds still constrain several denial-of-service dimensions.

## Network boundary

The service attaches only to the existing external `monitor` network. Port `9090/tcp` is exposed as container metadata but never published to the host. Health, readiness, and metrics have no application authentication; every peer on that Docker network is therefore part of their trust boundary.

Expected egress is:

- HTTPS to enabled feed endpoints;
- HTTP(S) to the configured CrowdSec LAPI;
- optional HTTP(S) notification endpoint when explicitly enabled.

Feed HTTP requires global and per-feed opt-in. LAPI HTTP requires an exact host allowlist entry. The example trusts only Docker DNS `crowdsec`; it does not trust arbitrary private IPs or localhost.

The native OCI healthcheck allows only loopback HTTP, exact `/healthz`, no credentials/userinfo/query/fragment, no redirects, bounded timeouts, and a bounded JSON body. This prevents the health command from becoming a general in-network fetch primitive.

## Secrets

No runtime credential is accepted through an image layer, build argument, Compose environment variable, or checked-in config. Machine credentials are a dedicated read-only file. Build context policy excludes the entire `secrets/` directory.

Crowdshield redacts credential values, feed bodies, response bodies, and sensitive parser details. This reduces accidental disclosure but does not make logs/scanner reports public artifacts. Preserve least-privilege access to logs, `.tmp` reports, backups, and CI artifacts.

## Supply-chain gates

CI uses read-only repository permissions, checkout without persisted credentials, pinned action commits, exact Go tool versions, and scanner/linter images pinned by digest. It does not publish images or request package/identity/deployment permissions.

Gates include:

- format, unit/race tests, vet, Staticcheck, gosec, and govulncheck;
- strict example/synthetic config tests and rendered Compose validation;
- Hadolint and ShellCheck;
- Gitleaks on Git history;
- static binary/material-module notice reconciliation;
- image metadata/rootfs/size inspection;
- isolated mock-LAPI container smoke tests;
- CycloneDX and SPDX SBOMs with pinned Syft;
- source/image Trivy vulnerability, secret, and misconfiguration reports;
- Go license inventory and checked-in verbatim notices.

Generated reports are kept under ignored `.tmp/` locally and uploaded as short-retention CI artifacts. Scanner failures are not waived in source or workflow config; a finding requires documented investigation and a narrowly reviewed resolution.

## Remaining assumptions

- The Docker host, daemon, BuildKit, registry transport, GitHub runner, and external `monitor` network are trusted administrative infrastructure.
- Immutable digests prevent tag drift but do not prove a base image is benign; signatures/provenance should be added if the selected registries provide a verified policy.
- CA trust follows the pinned distroless bundle; private LAPI CAs require a separately reviewed image/mount design rather than disabling TLS verification.
- A machine credential is more capable than a bouncer key. Crowdshield's ownership checks constrain application behavior, but CrowdSec still trusts the machine account.
- Port 9090 data is bounded and non-secret by design, but network peers can observe operational state and metrics.
- SQLite durability depends on reliable host storage and consistent stopped backups.
- Distroless intentionally limits live debugging. Diagnose via bounded logs, metrics, operator CLI, image/SBOM inspection, or a separate disposable debug environment—do not add a shell to production.
