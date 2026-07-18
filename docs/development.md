# Development and verification

Crowdshield development is designed to remain reproducible, test-first, and isolated from production CrowdSec and real feed state.

## Toolchain

Required:

- Go 1.26.5 (`GOTOOLCHAIN=local` for deterministic local use);
- Docker Engine, Buildx, and Compose v2;
- Python 3 for artifact verification scripts;
- Git.

CI additionally pins Staticcheck, gosec, govulncheck, Go license tooling, Hadolint, ShellCheck, Gitleaks, Syft, and Trivy. Exact action commits and container digests live in `.github/workflows/ci.yaml`.

Do not commit local tool installations, caches, reports, images, databases, credentials, or feed data. Use ignored `.tmp/` for generated evidence.

## Source gates

With Go on PATH:

```sh
go mod download
go mod verify
gofmt -w cmd internal migrations
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
```

A deterministic local binary build:

```sh
mkdir -p .tmp
CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false \
  -ldflags='-s -w -buildid=' -o .tmp/crowdshield ./cmd/crowdshield
file .tmp/crowdshield
scripts/verify-notices.py .tmp/crowdshield
```

The notice verifier fails if material modules embedded in the binary diverge from `THIRD_PARTY_NOTICES.md`. Update notices from exact upstream license files; do not infer a license from repository popularity or dependency-graph metadata.

## Container build

Use source-derived UTC metadata:

```sh
REVISION="$(git rev-parse --verify HEAD)"
EPOCH="$(git show -s --format=%ct HEAD)"
BUILD_DATE="$(date -u -d "@$EPOCH" '+%Y-%m-%dT%H:%M:%SZ')"
docker buildx build --platform linux/amd64 --load \
  --build-arg VERSION=dev \
  --build-arg REVISION="$REVISION" \
  --build-arg BUILD_DATE="$BUILD_DATE" \
  --build-arg SOURCE_DATE_EPOCH="$EPOCH" \
  --tag crowdshield:local .
```

Then run:

```sh
docker compose -f compose.yaml config --quiet
scripts/verify-image.py crowdshield:local
scripts/container-smoke.sh crowdshield:local
```

`verify-image.py` creates but never starts an inspection container, exports the visible rootfs under ignored `.tmp`, and removes the container in a `finally` block. It checks metadata, size, static linkage, ownership/modes, and forbidden payloads.

`container-smoke.sh` is the only daemon integration harness. It:

- builds a separate scratch-only mock LAPI image;
- creates a unique `--internal` Docker bridge;
- uses fixed synthetic credentials and a disabled `.invalid` feed;
- never attaches `monitor`, resolves production `crowdsec`, or publishes a port;
- checks version/help/unknown command, missing config/credential, invalid credential mode, and no-shell behavior;
- runs the daemon as the current numeric UID/GID with read-only root, no capabilities, and only `/data` writable;
- waits for the native Docker healthcheck, validates state ownership and mount behavior, then sends SIGTERM;
- removes every test container, network, mock image tag, and temporary directory on success or failure.

Never modify this harness to use real credentials, real feed contents, a production LAPI, `monitor`, or `docker compose up/down`.

## Security and license tools

The workflow is the canonical executable list. Representative exact-version source commands are:

```sh
go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...
go run github.com/securego/gosec/v2/cmd/gosec@v2.28.0 ./cmd/... ./internal/... ./migrations/...
go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...
go run github.com/google/go-licenses/v2@v2.0.1 report ./cmd/crowdshield
```

Container scanners are pinned by immutable digest in CI. Locally, write SBOM, vulnerability, secret, misconfiguration, license, and image-inspection reports under `.tmp/`; do not print complete generated reports into chat/logs. Run Gitleaks against Git history rather than an untracked working tree that may contain intentionally local credentials.

Do not add broad ignore files, `--ignore-unfixed`, severity downgrades, or scanner suppressions to make a gate green. Investigate each finding. If a false positive is proven, add the narrowest reviewed suppression with evidence and an expiry/review trigger.

## Test-first changes

For behavior changes:

1. add a focused failing test and capture the expected RED result;
2. implement the smallest change;
3. run the focused test GREEN;
4. run adjacent package and race tests;
5. run the full source/container/security gates before commit.

Tests must use `t.TempDir`, `httptest`, synthetic values, and `internal/lapi/mock`. Never place real feed snapshots or credentials in fixtures.

## Updating pins

For Go modules, base images, actions, or scanner images:

1. read upstream release/security notes;
2. resolve the exact module version, action commit, or multi-architecture manifest-list digest;
3. update all occurrences, including docs/notices;
4. refresh SBOM/license inventory;
5. rebuild without stale local layers where appropriate;
6. run all source, container, smoke, secret, vulnerability, license, and artifact gates;
7. review the complete diff once.

Readable tags may accompany digests, but the digest/commit is the trust anchor. Do not use `latest`, floating major action tags, or mutable package installation during runtime builds.

## Commit discipline

Before staging:

```sh
git status --short
git diff --check
git diff
```

Stage only reviewed source, packaging, workflow, and documentation files. Explicitly exclude `.tmp/`, `.tools/`, caches, `data/`, `.env`, databases, and `secrets/lapi-credentials.yaml`. Push normally—never force—and verify local HEAD, remote-tracking branch, GitHub branch head, and intended commit agree.
