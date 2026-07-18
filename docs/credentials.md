# CrowdSec machine credentials

Crowdshield needs a dedicated CrowdSec **machine** account. A bouncer key is insufficient: Crowdshield authenticates as a machine to create alerts, verify exact ownership, and expire only its own decisions.

The required in-container path is fixed by the deployment example:

```text
/run/secrets/crowdshield-lapi-credentials.yaml
```

Compose mounts the host file `secrets/lapi-credentials.yaml` read-only at that path.

## File shape

Use exactly one bounded YAML document with these fields:

```yaml
url: "https://crowdsec.example.internal:8080"
login: "crowdshield-REPLACE_WITH_UNIQUE_MACHINE_NAME"
password: "REPLACE_WITH_GENERATED_PASSWORD"
```

For the checked-in single-host Docker deployment, the endpoint may instead be:

```yaml
url: "http://crowdsec:8080"
login: "crowdshield-REPLACE_WITH_UNIQUE_MACHINE_NAME"
password: "REPLACE_WITH_GENERATED_PASSWORD"
```

Plain HTTP is accepted only when the hostname is explicitly listed in `crowdsec.allowed_http_hosts`; the example allowlists exactly `crowdsec`. Do not allowlist broad domains, arbitrary IP ranges, `localhost`, or user-controlled DNS. Use HTTPS across hosts or untrusted network segments.

Never paste a real password into documentation, shell history, environment variables, Compose YAML, image build arguments, Git, issue reports, or scanner artifacts.

## Provision on CrowdSec v1.7.8

The following v1.7.8 command contract was verified from the pinned CrowdSec image. `machines add/delete` operate directly on the CrowdSec database, so run them where `cscli` has the deployed CrowdSec configuration/database.

Choose a unique name so rotation can overlap safely:

```sh
umask 077
docker compose exec -T crowdsec \
  cscli machines add crowdshield-YYYYMMDD --auto \
  --url http://crowdsec:8080 --file - \
  > secrets/lapi-credentials.new.yaml
chmod 0600 secrets/lapi-credentials.new.yaml
```

`--file -` is important: without it, `--auto` defaults to writing `/etc/crowdsec/local_api_credentials.yaml` inside the CrowdSec environment and may overwrite an unrelated machine credential file. Do not use `--password VALUE`; it exposes the secret in process arguments and shell history.

Inspect only the non-secret structure with an editor or safe parser. Do not print the complete file. Verify metadata:

```sh
test -f secrets/lapi-credentials.new.yaml
test ! -L secrets/lapi-credentials.new.yaml
chmod 0600 secrets/lapi-credentials.new.yaml
chown "$(id -u):$(id -g)" secrets/lapi-credentials.new.yaml
stat -c '%u:%g %a %n' secrets/lapi-credentials.new.yaml
```

Set `CROWDSHIELD_UID/GID` to that numeric owner, or use a deliberately provisioned service UID/GID and chown both credentials and `data/` to it.

Validate shape and permissions with no network before activating the file:

```sh
docker run --rm --network none --read-only \
  --user "$(id -u):$(id -g)" --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --mount type=bind,src="$PWD/config/crowdshield.yaml",dst=/config/crowdshield.yaml,readonly \
  --mount type=bind,src="$PWD/secrets/lapi-credentials.new.yaml",dst=/run/secrets/crowdshield-lapi-credentials.yaml,readonly \
  crowdshield:local validate-config
```

This validates YAML, endpoint policy, regular-file/symlink checks, owner-compatible readability, and strict permissions. It does not authenticate.

## Activate initial credentials

```sh
mv secrets/lapi-credentials.new.yaml secrets/lapi-credentials.yaml
docker compose up -d --no-deps --force-recreate crowdshield
docker compose ps crowdshield
docker compose exec crowdshield /crowdshield status --json
```

A container recreation is required. Crowdshield reads credentials at process startup; replacing the host pathname does not safely rotate the already-open bind mount or in-memory credential set.

## Rotation without lockout

1. Record the old machine name without exposing its password.
2. Create a **new, uniquely named** machine with `--auto --file -`.
3. Validate the new file offline as above.
4. Keep a protected copy of the old file outside Git for immediate rollback.
5. Atomically replace `secrets/lapi-credentials.yaml` and force-recreate Crowdshield.
6. Verify Docker health, `status --json`, logs, LAPI machine heartbeat, and a dry-run sync.
7. Only after verification, delete the old machine account:

   ```sh
   docker compose exec crowdsec cscli machines list
   docker compose exec crowdsec cscli machines delete OLD_MACHINE_NAME
   ```

If activation fails, restore the old file, force-recreate Crowdshield, and leave the new CrowdSec account in place until the cause is understood. Deleting the old account first converts a reversible rotation into an outage.

## Compromise response

1. Treat the machine credential as write-capable for Crowdshield-owned alert/decision operations.
2. Provision and activate a new uniquely named account immediately.
3. Delete the compromised machine after successful cutover.
4. Inspect CrowdSec alerts/decisions and Crowdshield SQLite/log history for unexpected operations.
5. Rotate any secret-store or backup copies and review filesystem/access logs.
6. Do not paste the compromised value into tickets or chat; refer to its machine name and time window only.

## Loader guarantees and limitations

The credential loader requires a regular non-symlink file, strict mode with no group/other access, a bounded file/document/field size, an absolute configured path, a valid HTTP(S) endpoint, and non-empty bounded login/password fields. Rejected values and parser details are not emitted.

Filesystem ownership is deployment-specific. The process must be able to read the `0600` file under its configured numeric UID. Docker secrets implemented as root-owned `0444` files are intentionally incompatible with this stricter contract unless the deployment mechanism can preserve the required owner/mode.
