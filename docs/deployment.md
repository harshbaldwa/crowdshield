# Deployment and operations

This guide describes the checked-in `compose.yaml` deployment. It builds `crowdshield:local`; it does not publish an image and it never manages the external `monitor` network.

## Deployment contract

Expected repository-local runtime paths:

| Host path | Container path | Access | Required owner/mode |
|---|---|---|---|
| `config/crowdshield.yaml` | `/config/crowdshield.yaml` | read-only | regular file, readable by runtime UID |
| `secrets/lapi-credentials.yaml` | `/run/secrets/crowdshield-lapi-credentials.yaml` | read-only | regular non-symlink, runtime UID, `0600` |
| `data/` | `/data` | read-write | runtime UID/GID, normally `0750` |

`CROWDSHIELD_UID` and `CROWDSHIELD_GID` in `.env` must be numeric and must match the credential and data owners. The image default is distroless nonroot `65532:65532`; use a host-compatible numeric identity for bind mounts.

The only attached network is the existing external network named `monitor`. The service has no host port, privileged mode, host PID/IPC/network namespace, devices, or Docker socket.

## Prerequisites

1. Docker Engine, Buildx, and Docker Compose v2.
2. An existing external Docker network:

   ```sh
   docker network inspect monitor >/dev/null
   ```

3. CrowdSec LAPI attached to that network and resolvable as `crowdsec` (or a reviewed HTTPS endpoint reflected in both configuration and credentials).
4. A dedicated CrowdSec machine credential file; see [credentials.md](credentials.md).
5. Enough space for the local image, build cache, and SQLite history.

## Prepare files and ownership

```sh
cp config/crowdshield.example.yaml config/crowdshield.yaml
cp .env.example .env
install -d -m 0750 data secrets
```

Edit `config/crowdshield.yaml` and `.env`. Review every enabled feed, attribution/terms link, thresholds, allowlist, synchronization interval, and decision lifetime. Do not put passwords or notification tokens in the YAML file.

Provision the credential file using [credentials.md](credentials.md), then verify without printing it:

```sh
test -f secrets/lapi-credentials.yaml
test ! -L secrets/lapi-credentials.yaml
stat -c '%u:%g %a %n' secrets/lapi-credentials.yaml data
```

Expected credential mode is `600`; owner and group must agree with `.env`. The data directory should normally be `750` or stricter.

## Build metadata and reproducibility

The Dockerfile pins the Dockerfile frontend, Go builder, and distroless runtime by immutable digest. Supply deterministic source metadata:

```sh
export CROWDSHIELD_VERSION=dev
export CROWDSHIELD_REVISION="$(git rev-parse --verify HEAD)"
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
export CROWDSHIELD_BUILD_DATE="$(date -u -d "@$SOURCE_DATE_EPOCH" '+%Y-%m-%dT%H:%M:%SZ')"
docker compose build
```

`CROWDSHIELD_REVISION` must be `unknown` or a 40/64-character lowercase hexadecimal revision. Build dates are UTC RFC3339 seconds. Reproducing the image requires the same source tree, build arguments, target platform, pinned base digests, and compatible BuildKit implementation.

Inspect build provenance embedded in the executable and image:

```sh
docker run --rm --network none --read-only crowdshield:local version
docker image inspect crowdshield:local
```

## Validate and start

Validation checks strict YAML plus credential shape and permissions; it does not authenticate or synchronize:

```sh
docker compose run --rm --no-deps crowdshield validate-config
docker compose up -d crowdshield
docker compose ps crowdshield
```

Do not use production LAPI or real feeds for packaging tests. `scripts/container-smoke.sh` creates an internal-only network, disabled synthetic feed, and disposable mock LAPI.

## Startup and shutdown

At startup Crowdshield:

1. loads and validates bounded strict YAML;
2. opens a regular, non-symlink `0600` machine credential file;
3. opens and migrates SQLite state under `/data` and optionally checks integrity;
4. recovers interrupted synchronization records and prunes bounded history when due;
5. authenticates to CrowdSec LAPI;
6. starts the health/metrics server and scheduler.

A startup dependency failure exits nonzero with a fixed diagnostic. No supervisor is bundled. Docker restart policy handles retries.

The Go binary is PID 1, installs SIGINT/SIGTERM handling, starts no child-process workload, and reaps no external workers; therefore `init: true` is unnecessary. Compose allows 20 seconds for scheduler cancellation, HTTP shutdown, connection cleanup, credential destruction, and SQLite close.

```sh
docker compose stop crowdshield
docker compose start crowdshield
```

A normal SIGTERM should produce exit code 0. Repeated forced kills can leave an interrupted synchronization record; startup recovery is designed to mark it safely, but graceful stop is preferred.

## Health and metrics

Port 9090 is available only on `monitor` unless an operator adds another network or proxy.

| Endpoint | Meaning | Success |
|---|---|---|
| `/healthz` | HTTP runtime is alive | 200, `{"status":"alive"}` |
| `/readyz` | config, credentials, DB, LAPI grace, runtime state, and recent safe sync permit service | 200; otherwise 503 with bounded JSON |
| `/metrics` | Prometheus metrics | 200 |

Only GET and HEAD are accepted for health/readiness. Responses disable caching and MIME sniffing. These endpoints have no application authentication; preserve the network boundary.

Docker health uses `/crowdshield healthcheck`, which permits only loopback HTTP and exact `/healthz`, follows no redirects, bounds timeout/body, and loads no config or credentials.

```sh
docker compose exec crowdshield /crowdshield healthcheck
docker compose exec crowdshield /crowdshield status --json
```

`status` returns exit 3 while not ready. A fresh database may remain not ready until the first safe synchronization completes.

## Routine operator commands

Run read operations in the existing service container so they use the same mounts and identity:

```sh
docker compose exec crowdshield /crowdshield status --json
docker compose exec crowdshield /crowdshield list-feeds --json
docker compose exec crowdshield /crowdshield explain --json 203.0.113.10
docker compose exec crowdshield /crowdshield db check
```

Preview synchronization without persistence or LAPI writes:

```sh
docker compose exec crowdshield /crowdshield sync --dry-run --json
docker compose exec crowdshield /crowdshield sync --dry-run --feed spamhaus-drop-ipv4 --json
```

Omitting `--dry-run` can create/refresh/expire Crowdshield-owned LAPI decisions and update SQLite. Treat it as a live change.

Pruning is plan-only unless the exact confirmation is supplied:

```sh
docker compose exec crowdshield /crowdshield prune --json
docker compose exec crowdshield /crowdshield prune --json --confirm DELETE-EXPIRED-CROWDSHIELD-HISTORY
```

Ownership conflicts return exit 4 and block destructive action. Investigate rather than bypassing them.

## Consistent backup and restore

Crowdshield does not ship a SQLite CLI or online-backup command. Use a stopped copy of the **entire** data directory; do not copy only the main `.db` file while the service runs because WAL/SHM state may be active.

Backup:

```sh
docker compose stop crowdshield
install -d -m 0700 backups
tar --numeric-owner -C data -cpf "backups/crowdshield-data-$(date -u +%Y%m%dT%H%M%SZ).tar" .
docker compose start crowdshield
docker compose exec crowdshield /crowdshield db check
```

Store the matching image digest, configuration, and build metadata with the backup record. Back up credentials separately in an access-controlled secret store; never put them in the data archive or Git.

Restore:

1. Stop Crowdshield.
2. Preserve the current `data/` as a rollback copy.
3. Restore the complete archive into an empty `data/` directory.
4. Restore numeric ownership/mode for the configured runtime UID/GID.
5. Start the image version associated with that backup.
6. Run `db check`, inspect status, and perform a dry-run sync before live writes.

Do not assume a previous image can read a database after newer migrations. Roll back image and data together.

## Upgrade and rollback

1. Read release/diff notes and changed feed terms.
2. Take a consistent stopped data backup.
3. Build with a reviewed source revision and record image ID/SBOM/scan results.
4. Validate configuration/credentials with the candidate image.
5. Recreate only Crowdshield, then verify image metadata, health, readiness, logs, metrics, and a dry run.

```sh
docker compose up -d --no-deps --force-recreate crowdshield
```

Rollback uses the previous image **and** its matching data backup if the candidate applied a migration. Do not force an old binary against a newly migrated database.

## Troubleshooting

| Symptom | Safe first checks |
|---|---|
| `configuration invalid` / exit 2 | strict field names, absolute paths, duration/threshold bounds, credential regular-file mode/owner, unknown `CROWDSHIELD_*` variables |
| `runtime failed` / exit 1 | container logs, LAPI DNS/TLS, machine account validity, `/data` ownership/free space, SQLite integrity |
| Docker `unhealthy` | process still running, `/healthz` listener, PID/CPU pressure; native probe intentionally does not test dependencies |
| `/readyz` 503 or status exit 3 | bounded readiness reason, last safe sync age, LAPI grace, feed validation failures, startup state |
| exit 4 | foreign/ambiguous ownership; inspect exact alert/decision state and do not force prune/reconcile |
| restart loop | run `validate-config` as the exact UID, inspect fixed error category, verify mounts and external network |
| credential works outside container only | generated URL points to loopback or wrong DNS; use `crowdsec` on `monitor` or reviewed HTTPS |
| read-only filesystem error | only `/data` is writable; fix the configured database path rather than adding `/tmp` |

Logs are JSON and intentionally omit credentials, URLs with userinfo, response bodies, and raw feed contents. Keep debug logs and generated scanner reports access-controlled anyway.
