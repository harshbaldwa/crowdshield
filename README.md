# Crowdshield

Crowdshield is a conservative CrowdSec external-feed synchronizer. It downloads reviewed IP/network feeds, validates and normalizes their entries, and reconciles only Crowdshield-owned CrowdSec alerts and decisions. It is designed to fail closed around malformed input, ownership ambiguity, credentials, and partial synchronization.

Crowdshield is not a CrowdSec bouncer and does not consume a bouncer API key. It uses a dedicated CrowdSec **machine** account because it must authenticate, create alerts, inspect exact ownership, and expire only its own decisions.

The project is pre-1.0 and currently builds a local image only. No registry publication or automatic deployment is configured.

## Safety model

- Crowdshield-owned scenarios use the `crowdshield/<feed>` namespace.
- Foreign alerts and decisions are never adopted or deleted.
- Dry-run synchronization performs no persistence or LAPI writes.
- Feed downloads are bounded by timeout, size, content type, redirect, syntax, and change-rate checks.
- Configuration and credential errors produce fixed diagnostics rather than rejected values.
- The container runs without root, Linux capabilities, a shell, package manager, `curl`, or `wget`.
- Compose uses a read-only root filesystem; only `/data` is writable.
- Configuration and machine credentials are read-only bind mounts.
- Port 9090 is exposed only to the external `monitor` Docker network; there is no host port mapping.

See [the threat model](docs/threat-model.md) and [container security rationale](docs/container-security.md) for the complete trust boundaries.

## Quick start

Prerequisites: Docker Engine with Buildx and Compose v2, an existing external Docker network named `monitor`, and a CrowdSec LAPI reachable as `crowdsec` on that network.

```sh
cp config/crowdshield.example.yaml config/crowdshield.yaml
install -d -m 0750 data secrets
# Provision secrets/lapi-credentials.yaml as described in docs/credentials.md.
cp .env.example .env
# Set CROWDSHIELD_UID/GID to the numeric owner of data and the credential file.
docker compose build
docker compose run --rm --no-deps crowdshield validate-config
docker compose up -d crowdshield
docker compose ps crowdshield
```

The checked-in example deliberately permits plaintext LAPI HTTP only for the exact internal DNS host `crowdsec`. Prefer HTTPS whenever the LAPI trust domain crosses hosts or untrusted networks.

Detailed prerequisites, build metadata, permissions, health behavior, backup/restore, upgrades, rollback, and troubleshooting are in [docs/deployment.md](docs/deployment.md).

## CLI

```text
crowdshield run [--run-once] [--config PATH]
crowdshield sync [--dry-run] [--feed NAME] [--json] [--config PATH]
crowdshield status [--json] [--config PATH]
crowdshield validate-config [--config PATH]
crowdshield list-feeds [--json] [--config PATH]
crowdshield explain [--json] [--config PATH] ADDRESS_OR_PREFIX
crowdshield prune [--json] [--confirm DELETE-EXPIRED-CROWDSHIELD-HISTORY] [--config PATH]
crowdshield db check [--config PATH]
crowdshield healthcheck [--url http://127.0.0.1:9090/healthz] [--timeout 2s]
crowdshield version
crowdshield help
```

Exit codes are stable: `0` success, `1` operational failure, `2` invalid usage/configuration, `3` degraded or not ready, and `4` ownership conflict.

## Observability

The service listens on port 9090 inside the `monitor` network:

- `GET|HEAD /healthz` — process liveness, HTTP 200 while the HTTP server is alive.
- `GET|HEAD /readyz` — dependency and synchronization readiness, HTTP 200 or 503 with bounded JSON state.
- `GET /metrics` — Prometheus metrics.

The OCI/Docker healthcheck uses the native `crowdshield healthcheck` command against loopback `/healthz`; it does not load configuration or credentials and does not require a shell.

## Documentation

- [Deployment and operations](docs/deployment.md)
- [Machine credentials and rotation](docs/credentials.md)
- [Container and supply-chain security](docs/container-security.md)
- [Development and verification](docs/development.md)
- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [CrowdSec API assumptions](docs/api-assumptions.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)
- [Security reporting](SECURITY.md)
- [Current project checkpoint](docs/PROJECT_STATE.md)

## License

Crowdshield is licensed under the MIT License. See [LICENSE](LICENSE). Material runtime dependency notices and feed-data terms are recorded in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
