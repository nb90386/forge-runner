# Operator setup for ARM64 synthetic conformance

Run from the runner checkout. No step authorizes agent execution, leases or a
production deployment. The setup script never pulls, pushes, logs in, mounts host
paths, discovers credentials or starts a service. Only `build` builds; only `live`
starts Forge's fixed disposable probes. `audit` is read-only and does not attest
isolation. Python 3.9+ and a trusted Linux ARM64 Python base are required.

## Audit findings (2026-10-28, this restricted session)

- PATH Docker: `/Users/edge/.orbstack/bin/docker` is a symlink to
  `/Applications/OrbStack.app/Contents/MacOS/xbin/docker-tools`.
  The target is accepted as an executable spelling only at the exact canonical target path.
  The symlink remains refused, and all ownership and ancestor permission checks
  still apply. `/Applications` was mode 0775 in this audit, so that installation
  remains blocked. An independently trusted standalone CLI named `docker` under
  a private canonical path is another option. Do not change system permissions
  as a workaround. CLI provenance remains an operator responsibility.
- Orb CLI is also a symlink into OrbStack.app. No Orb command or VM was started.
- Selected Docker context reports `unix:///Users/edge/.orbstack/run/docker.sock`.
  That path is an actual Unix socket and passes checked_path. `/var/run/docker.sock`
  is a symlink and is refused. Context inspection was discovery only; setup and
  conformance use an explicit endpoint and an empty Docker configuration.
- Image inventory and daemon info requests failed with permission denied.
  Available Python images, image configurations, repository digests, daemon
  identity and isolation capabilities are **UNKNOWN**, not empty or verified.
  Docker's partial info output with empty ID/false limits is not usable evidence.
- No trusted base digest was supplied or independently verified. **STOP until one
  is available.** No digest in this guide is an asserted real digest. No build,
  pull, push or live conformance was performed during this audit.

## 1. Establish trust and inspect prerequisites

Choose an exact Python slim release from the Docker Official Image `python`
maintainer's published metadata. Independently verify its publisher/provenance
and the registry manifest digest (not a local image ID). Record the release,
source URL, verification date, ARM64 child manifest if using a multiarch index,
and digest evidence in an operator audit record. A digest provides integrity,
not publisher trust. A locally present image or copied RepoDigest alone does not
establish trust. If authoritative metadata cannot be obtained, stop.

The base must already be locally provisioned through your separately approved
image supply process. This script does not obtain it. It must have Linux/arm64
filesystem content, `/usr/local/bin/python3` (Python >=3.9), the standard library
including resource/socket/tarfile, its shared libraries, and no ONBUILD triggers.
Audit the base filesystem for secrets and unexpected executables. The Dockerfile
copies that filesystem in full; it is a minimal recipe, not a distroless reduction.
Stock Python image environment variables are removed by the final scratch stage;
setting them to empty strings would still violate Forge's PATH-only rule.

Set real values from your audit; these parameter expansions deliberately stop
when a value is absent. Never replace a digest with guessed hex characters.

```sh
: "${DOCKER:?canonical trusted executable named docker required}"
: "${SOCKET:?canonical Unix socket required}"
: "${BASE:?independently verified already local python repository@sha256 digest required}"

# Read-only discovery, with no personal context or credential helpers.
CFG=$(mktemp -d)
trap 'rmdir "$CFG"' EXIT
engine() { env -i PATH=/usr/bin:/bin HOME="$CFG" DOCKER_CONFIG="$CFG" \
  "$DOCKER" --host "unix://$SOCKET" "$@"; }
engine version --format '{{json .Server}}'
engine info --format '{{.ID}} {{.OSType}} {{.Architecture}} {{.CgroupVersion}} {{.MemoryLimit}} {{.SwapLimit}} {{.CpuCfsQuota}} {{.PidsLimit}}'
engine image ls --digests --no-trunc
engine image inspect "$BASE" --format '{{.Id}} {{json .RepoDigests}} {{.Os}}/{{.Architecture}} {{json .Config}}'
```

Do not publish raw inventory/configuration output; unrelated images may contain
sensitive metadata. Stop on any error. Required daemon reports are Linux, a nonempty
ID, and true memory/swap/CPU quota/PID limits. Cgroup v2 files and their effective
bounds are checked by live probes. CLI inspection is never conformance.

## 2. Build the fixture explicitly

```sh
python3 tools/container-fixture/setup.py build \
  --docker "$DOCKER" --socket "$SOCKET" \
  --base "$BASE" --trust-base --tag forge-conformance:arm64
```

`--trust-base` records your explicit decision, not an automated provenance check.
Missing local base, wrong architecture/digest, build triggers, unsafe CLI/socket
paths or failed builder stop the script. The build context contains only the
reviewed Dockerfile, never this checkout, home, SSH keys, credentials or socket.
There are no RUN instructions or package downloads. Builder subprocesses use an
empty configuration/environment. A trusted system-installed Buildx may be needed;
user plugins and contexts are deliberately unavailable. Do not retry with personal
Docker config or mount credentials to fix a builder failure.

`--pull=false` avoids forcing a newer base; BuildKit may still query registry
metadata. `--network=none` concerns build RUN networking, not the builder daemon.
For an entirely offline build, enforce registry egress denial at the trusted
builder/daemon and use its already local base. Do not claim that these flags alone
prevent all daemon network access. The script never invokes `docker pull`.
The fixed base and SOURCE_DATE_EPOCH=0 support repeatable builds; record Docker,
Buildx and daemon versions too. Cross-builder byte-identical output is unverified.

Save `built_id` from the JSON output as `EXPECTED_ID`. It is a configuration image
ID, **not** a repository manifest digest. Build output remains UNVERIFIED.

## 3. Provision the exact built fixture with a real repository digest

A local build/tag usually has no RepoDigests. Do not fabricate one from built_id,
edit Docker metadata, relax the adapter, or approve only a tag. Use an existing,
operator-approved distribution registry and your separately authorized image
supply process. For example, with the `engine` helper above and an existing
registry allowing credential-free access from this trusted daemon:

```sh
: "${EXPECTED_ID:?built_id from the successful build required}"
: "${FIXTURE_TAG:?existing approved registry/repository:unique-tag required}"
engine image tag "$EXPECTED_ID" "$FIXTURE_TAG"
engine image push "$FIXTURE_TAG"
```

These are explicit operator supply steps, not actions performed by setup.py. Do
not start a registry, enable insecure registries, deploy a service or use personal
credentials as part of this setup. If your registry needs authentication, stop and
use your separately approved supply process. Preserve the push's manifest digest,
independently verify it against registry metadata, and set IMAGE to that exact
repository@sha256 digest. It must be locally inspectable on the selected daemon;
if distribution occurred elsewhere, local provisioning is a separate operator
prerequisite. Never substitute the base digest for the fixture digest.

```sh
: "${IMAGE:?independently verified fixture repository@sha256 digest required}"
python3 tools/container-fixture/setup.py audit \
  --docker "$DOCKER" --socket "$SOCKET" \
  --image "$IMAGE" --expected-id "$EXPECTED_ID"
python3 tools/container-fixture/setup.py live \
  --docker "$DOCKER" --socket "$SOCKET" \
  --image "$IMAGE" --expected-id "$EXPECTED_ID"
```

Audit requires the exact RepoDigest, matching build ID, Linux/arm64, exact PATH,
UID/GID 65534, /workspace, no CMD/entrypoint/volumes/triggers/healthcheck, and daemon
limits. Live binds the expected build ID through conformance, creates by that immutable
ID, and checks the digest mapping and actual container image before starting each
probe by container ID. Live additionally verifies actual `/usr/local/bin/python3` >=3.9 and every
existing isolation, resource, cancellation, capture, artifact and cleanup probe.
Only live JSON status PASS/exit 0 attests this invocation. Audit success is still
UNVERIFIED. Any missing isolation guarantee or cleanup uncertainty fails closed.
Neither result is an agent execution permit. LEASES.md blockers remain unchanged.

## Diagnostics and cleanup

Setup exits 1 with a runner-owned refusal message, avoiding daemon error/secret leakage.
Use the sanitized engine helper for targeted `version`, `info`, `image inspect`
and `ps --all --filter name=forge-fixture-` inspection locally. Permission denied
means daemon availability is unknown; run from an operator session with socket
access, without loosening socket permissions. Missing RepoDigests requires proper
distribution, not a tag or image ID. Unsupported limits or failed probes block
conformance; do not bypass them or use host execution as a fallback.

Forge removes each uniquely named fixture and confirms absence, including after
probe failure. On interruption/cleanup refusal, list candidates, inspect each
exact name and configuration, then remove only confirmed fixtures from this run:

```sh
engine ps --all --filter name=forge-fixture- --format '{{.Names}}'
# Set NAME to one individually inspected fixture, never a wildcard:
: "${NAME:?exact confirmed fixture name required}"
engine inspect "$NAME"
engine rm --force "$NAME"
engine ps --all --filter "name=^/$NAME$" --format '{{.Names}}'
# Optional removal of this setup's local tag only (no prune/force):
engine image rm forge-conformance:arm64
```

Confirm absence before retrying. Do not delete unrelated containers/images or the
shared base. Registry retention and remote fixture cleanup belong to your existing
supply process. CLI/daemon compromise, hostile same-account path races, host crash
cleanup and CPU scheduling fairness remain outside this evidence.

References: [Dockerfile](https://docs.docker.com/reference/dockerfile/),
[Buildx build](https://docs.docker.com/reference/cli/docker/buildx/build/),
[image digests](https://docs.docker.com/dhi/core-concepts/digests/).
Context7 lookup was attempted but failed with DNS/fetch errors; sandbox policy
prevented an outside-sandbox retry. Official Docker web documentation was consulted.

Offline verification from the checkout (no Docker needed):

```sh
PYTHONPATH=src:tests python3 -m unittest test_container_setup test_container.ContainerTests test_conformance -v
python3 -m compileall -q src tests tools/container-fixture
git diff --check
```

Full discovery is `python3 -m unittest discover -s tests -v`. In this audit it
ran 115 tests before the final additional build-context test: one existing staging
failure (sandbox denied loopback bind) and 11 skips. The focused setup tests,
including the additional mocked build-context test, passed; actual Unix socket
binding was denied and skipped. Compilation and diff checks passed. These are
offline results, not evidence of Docker image or isolation validity.
