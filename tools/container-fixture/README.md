# Operator setup for ARM64 synthetic conformance

**Current status: ready for an operator synthetic live test; isolation unverified.**
Runtime, audit and live conformance use a private Docker Engine API v1.45 client
over the approved OrbStack Unix socket, without Docker CLI subprocesses. Only
fixed synthetic operations are supported. The legacy `build` action is refused
by this client; provision the independently audited fixture separately. Real
agent execution remains disabled. No daemon was contacted during this repair.

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

For a live failure, opt in to local redacted diagnostics using the same audited
configuration and approved image:

```sh
python3 tools/container-fixture/setup.py live --diagnostics \
  --docker "$DOCKER" --socket "$SOCKET" \
  --image "$IMAGE" --expected-id "$EXPECTED_ID"
```

The flag is live-only, defaults off, and adds one fixed `diagnostic` object on
conformance failure. `probe` identifies `daemon` or one of the six fixed probes;
`stage` identifies daemon/image checks, create/ID, restrictions, identity recheck,
start/stop, exit state, artifact parsing, result validation, or cleanup
remove/confirmation. `code` is only `refused`, `interrupted`, or
`result_mismatch`. Unknown details become `unknown`/`refused`. Cleanup failure
takes precedence over an earlier probe failure because absence is unconfirmed.
Expected timeout/cancellation is validated as a result, not reported as a failure.
A result mismatch does not reveal the internal assertion or raw exit status.
No Docker stderr, container output, exception text, environment, credentials,
image metadata, or discovered host paths are included in diagnostic JSON.
Detected executable paths are omitted and engine candidates become booleans in
this mode. Setup preflight failures retain their fixed refusal messages.

Failures leave all eight guarantees UNVERIFIED and both execution flags false.
Diagnostics do not authorize execution or change the fixture, restrictions,
identity checks, deadlines, cancellation, or cleanup. Do not loosen protections
in response to a code. For example, `probe/restrictions/refused` means the
inspected effective configuration was refused; it does not establish which
field differs. `probe/result/result_mismatch` means the fixed isolation probe
did not complete successfully; Python/UID/capability/no-new-privileges, filesystem,
network, and cgroup checks can all fail inside that probe. Resource exhaustion,
capture bounds, artifact validation, timeout and cancellation each have a
separate probe identifier. A stage code narrows investigation without asserting
the cause of the observed local failure.


### Docker 29 digest metadata compatibility

Setup and runtime compare repository digest evidence after Docker Hub name
normalization: `python`, `library/python`, `docker.io/python`, and
`docker.io/library/python` name the same repository (as does the legacy
`index.docker.io` spelling). The SHA256 digest must still match exactly.
Other registry hosts, ports, namespaces and repository paths remain distinct;
`registry-1.docker.io` is not treated as an alias. The supplied digest reference
is still used for inspection and the build argument; provenance approval,
platform checks, immutable image selection and build flags are unchanged.

The former literal string comparison rejected equivalent Hub names. This is a
code-level cause, not a confirmed diagnosis of the local OrbStack installation:
read-only daemon inspection in this session was denied socket access, so neither
the actual RepoDigests representation nor its absence could be established.
Regression tests use synthetic canonical/familiar metadata, not captured daemon
output. Docker 29 alone does not establish which metadata the engine returns.

Missing, empty or mismatched RepoDigests remains **BLOCKED**, even when inspection
by digest succeeds or an image ID, tag or Descriptor digest matches. No such
field alone proves the approved repository-to-manifest association. Do not
derive a manifest digest from the local configuration ID or edit engine metadata.

Safe provisioning alternative (a separate operator action, not performed here):
use an approved engine/distribution process that preserves inspectable repository
digests. Independently verify the approved publisher and registry manifest bytes
against the trusted SHA256 digest. For a multiarch index, verify the index digest,
its Linux ARM64 child manifest digest, and the child's configuration digest.
Provision that exact repository digest on the selected trusted engine, then
confirm RepoDigests, Linux/arm64 and the configuration ID before retrying setup.
If this engine cannot expose the required association, use a separately approved
compatible engine; the fixture build stays blocked on this one. An archive or
local tag without that association is insufficient. This does not authorize a
pull, push, registry deployment or engine reconfiguration from this session.

Normalization follows the upstream
[Docker reference implementation](https://github.com/distribution/reference/blob/main/normalize.go).

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

### Resource-result mismatch investigation

The old resource fixture expected a 512 MiB allocation under a 256 MiB cgroup
limit to raise Python `MemoryError`. Linux may instead OOM-kill the allocating
process. Exit 137 alone cannot distinguish this from another SIGKILL. The updated
fixture allocates in a child and requires memory-limit event evidence; an OOM
kill additionally requires an increased `oom_kill` counter. PID exhaustion must
raise EAGAIN with an increased `pids.events:max`, and forks are bounded even if
enforcement is absent. Missing event support fails closed.

To distinguish the original allocation assumption from other local failures,
run this disposable memory-only diagnostic with the same previously audited
`DOCKER`, `SOCKET`, `IMAGE` and `EXPECTED_ID` values. It uses the adapter's normal
restrictions, digest/ID checks, deadline and confirmed removal. It neither
attests conformance nor authorizes execution. No image is pulled or built.

```sh
PYTHONPATH=src python3 - <<'PY'
import json, os
import forge.container as container
from forge.runtime import Limits
adapter = container.ContainerAdapter(container.ContainerConfig(
    os.environ['DOCKER'], os.environ['SOCKET'], os.environ['IMAGE'],
    os.environ['EXPECTED_ID']))
adapter._check_daemon()
container.FIXTURE = '''
import os
assert os.getuid() == 65534
assert int(open('/sys/fs/cgroup/memory.max').read()) == 268435456
try:
    a = bytearray(536870912)
except MemoryError:
    print('allocation-refused', flush=True)
else:
    raise AssertionError('allocation succeeded')
'''
inspect = adapter._inspect_container
def observe(cid):
    obj = inspect(cid)
    state = obj.get('State', {})
    if state.get('Status') == 'exited':
        print(json.dumps({'oom_killed': state.get('OOMKilled'),
                          'exit_code': state.get('ExitCode')}))
    return obj
adapter._inspect_container = observe
result = adapter._run('resource-fixture', Limits(wall_seconds=3, grace_seconds=1))
print(json.dumps({'status': result[0], 'exit_code': result[1]}))
PY
```

`oom_killed=true` with exit 137 supports the original probe-assumption failure.
Timeout or a different exit requires further investigation; it is not PASS.
Successful allocation is a resource enforcement failure. A zero exit in this
diagnostic means only that Python received MemoryError; full live conformance
must still pass with the updated event checks.

Effective-limit evidence now requires a host-rooted cgroup v2 mount and an
unambiguous membership path. The probe reads cpu.max, memory.max and pids.max
through the entire ancestry, compares the minimum CPU quota/period ratio and
byte/process limits against the exact request, and refuses missing evidence.
Hosts that hide or omit ancestor controller files remain unverified.
Timeout and cancellation require a child-to-parent pipe handshake, an attached
startup marker, and a running-container inspection before termination.
Cancellation requires a complete newline-terminated marker and genuine running
state with a PID and start timestamp. The attached stream remains open while the
fixture runs; partial markers never count. Exit state requires zero PID and
start/finish timestamps. Cleanup requires forced removal and an empty exact-name
lookup. No host CLI supervisor or subprocess is used by runtime or conformance.
