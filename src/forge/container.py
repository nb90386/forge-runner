"""Docker-compatible synthetic sandbox. No repository code or host mounts.

Conformance is deliberately process-local and must be earned against the daemon.
The operator supplies an audited, locally provisioned Python image by digest.
"""
from dataclasses import dataclass
import io
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import tarfile
import tempfile
import time
import uuid

from .safety import SafetyError, checked_path


def has_repository_digest(image, reference):
    """Match SHA256 provenance, allowing only Docker Hub name aliases.

    Never infer registry provenance from an image ID, tag, or descriptor.
    Keep non-Hub registries (including registry-1.docker.io) distinct.
    """
    def canonical(value):
        if not isinstance(value, str) or not re.fullmatch(
                r'[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}', value):
            return None
        repository, digest = value.split('@')
        first, separator, rest = repository.partition('/')
        if not separator:
            repository = 'docker.io/library/' + repository
        elif first in ('docker.io', 'index.docker.io'):
            repository = 'docker.io/' + (rest if '/' in rest else 'library/' + rest)
        elif first != 'localhost' and '.' not in first and ':' not in first:
            repository = 'docker.io/' + repository
        return repository + '@' + digest

    expected = canonical(reference)
    digests = image.get('RepoDigests')
    return (expected is not None and isinstance(digests, list)
            and any(canonical(value) == expected for value in digests))


@dataclass(frozen=True)
class ContainerConfig:
    executable: str
    socket: str
    image: str
    expected_id: str = None

    def validate(self):
        binary = checked_path(self.executable)
        endpoint = checked_path(self.socket)
        orbstack = '/Applications/OrbStack.app/Contents/MacOS/xbin/docker-tools'
        if ((binary.name != 'docker' and str(binary) != orbstack)
                or not binary.is_file() or not os.access(binary, os.X_OK)
                or not endpoint.is_socket()):
            raise SafetyError('local container executable and Unix socket required')
        if not re.fullmatch(r'[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}', self.image):
            raise SafetyError('audited image must have an immutable digest')
        if self.expected_id is not None and not re.fullmatch(r'sha256:[0-9a-f]{64}', self.expected_id):
            raise SafetyError('valid audited image ID required')


# Never interpolated with repository content, descriptions, or caller commands.
FIXTURE = r'''
import os, sys, time, socket, resource
op = sys.argv[1]
if op == 'probe':
    assert sys.executable == '/usr/local/bin/python3' and sys.version_info >= (3, 9)
    assert os.getuid() == 65534
    status = open('/proc/self/status').read()
    assert 'CapEff:\t0000000000000000' in status
    assert 'NoNewPrivs:\t1' in status
    for p in ('/root', '/host', '/var/run/docker.sock'):
        assert not os.path.exists(p) or p == '/root' and not os.access(p, os.R_OK)
    try: open('/escape', 'w'); raise AssertionError('writable root')
    except OSError: pass
    os.symlink('/escape', '/workspace/link')
    try: open('/workspace/link', 'w'); raise AssertionError('symlink escape')
    except OSError: pass
    s = socket.socket(); s.settimeout(.2)
    try: s.connect(('192.0.2.1', 80)); raise AssertionError('network allowed')
    except OSError: pass
    for name in ('cpu.max', 'memory.max', 'pids.max'):
        value = open('/sys/fs/cgroup/' + name).read().strip()
        assert value and value.split()[0] != 'max'
    print('conformant')
elif op == 'capture-fixture':
    os.write(1, b'x' * 2097152); os.write(2, b'y' * 2097152)
elif op == 'artifact-fixture':
    import tarfile
    os.mkdir('/workspace/artifacts'); open('/workspace/artifacts/result.txt','w').write('synthetic artifact\n')
    with tarfile.open(fileobj=sys.stdout.buffer, mode='w|') as tar:
        tar.add('/workspace/artifacts/result.txt', arcname='result.txt', recursive=False)
elif op in ('timeout-fixture', 'cancel-fixture'):
    import signal
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    if os.fork() == 0:
        while True: time.sleep(1)
    while True: time.sleep(1)
elif op == 'resource-fixture':
    children = []
    try:
        while True:
            pid = os.fork()
            if pid == 0: time.sleep(60); os._exit(0)
            children.append(pid)
    except OSError: pass
    finally:
        for pid in children: os.kill(pid, 9); os.waitpid(pid, 0)
    try: a = bytearray(536870912); raise AssertionError('memory unbounded')
    except MemoryError: pass
'''


class ContainerAdapter:
    def __init__(self, config):
        if type(config) is not ContainerConfig:
            raise SafetyError('typed container configuration required')
        config.validate()
        self.config = config
        self._attested = False
        self._daemon = None
        self._failed = False
        self._image_id = config.expected_id

    def _cli(self, args, *, timeout=10, caps=(1048576, 1048576), cancellation=None):
        # Empty Docker configuration prevents credential helpers, contexts/plugins,
        # proxy variables and caller DOCKER_HOST from entering this boundary.
        with tempfile.TemporaryDirectory(prefix='forge-docker-') as config_dir:
            env = {'PATH': '/usr/bin:/bin', 'HOME': config_dir, 'DOCKER_CONFIG': config_dir}
            command = [self.config.executable, '--host', 'unix://' + self.config.socket, *args]
            with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, env=env, cwd=config_dir,
                                  start_new_session=True) as proc:
                streams = selectors.DefaultSelector()
                output = [bytearray(), bytearray()]
                for index, stream in enumerate((proc.stdout, proc.stderr)):
                    os.set_blocking(stream.fileno(), False)
                    streams.register(stream, selectors.EVENT_READ, index)
                deadline = time.monotonic() + timeout
                try:
                    while streams.get_map():
                        if time.monotonic() >= deadline or cancellation and cancellation.requested:
                            raise TimeoutError('container supervision interrupted')
                        for key, _ in streams.select(.05):
                            chunk = os.read(key.fd, 16384)
                            if not chunk:
                                streams.unregister(key.fileobj)
                            else:
                                target = output[key.data]
                                target.extend(chunk[:max(0, caps[key.data] - len(target))])
                    code = proc.wait(timeout=max(.01, deadline - time.monotonic()))
                finally:
                    streams.close()
                    if proc.poll() is None:
                        proc.terminate()
                        try: proc.wait(timeout=.2)
                        except subprocess.TimeoutExpired: proc.kill(); proc.wait()
                return code, bytes(output[0]), bytes(output[1])

    def _json(self, args):
        code, out, _ = self._cli(args)
        if code: raise SafetyError('container engine refused')
        return json.loads(out)

    def _check_daemon(self):
        info = self._json(['info', '--format', '{{json .}}'])
        if (info.get('OSType') != 'linux' or not info.get('ID')
                or not all(info.get(k) is True for k in ('MemoryLimit', 'SwapLimit', 'CpuCfsQuota', 'PidsLimit'))):
            raise SafetyError('required daemon limits unavailable')
        daemon = info['ID']
        if self._daemon is not None and self._daemon != daemon:
            raise SafetyError('daemon identity changed')
        self._daemon = daemon
        self._check_image()

    def _check_image(self):
        image, = self._json(['image', 'inspect', self.config.image])
        image_id = image.get('Id', '')
        if (not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id)
                or (self._image_id is not None and image_id != self._image_id)
                or not has_repository_digest(image, self.config.image) or image['Config'].get('Volumes')
                or any(not value.startswith('PATH=') for value in image['Config'].get('Env') or [])):
            raise SafetyError('image digest, ID, volumes or environment refused')
        self._image_id = image_id

    def _inspect_container(self, container):
        obj, = self._json(['inspect', container])
        if (obj.get('Id') != container or obj.get('Image') != self._image_id
                or obj.get('Config', {}).get('Image') != self._image_id):
            raise SafetyError('created container image identity mismatch')
        return obj

    def _run(self, operation, limits, cancellation=None):
        name = 'forge-fixture-' + uuid.uuid4().hex
        created = False
        container = name
        try:
            self._check_image()
            args = ['create', '--pull=never', '--name', name, '--network=none', '--read-only',
                    '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--user=65534:65534',
                    '--cpus=' + str(limits.cpu), '--memory=' + str(limits.memory_bytes),
                    '--memory-swap=' + str(limits.memory_bytes), '--pids-limit=' + str(limits.processes),
                    '--ipc=private', '--log-driver=none', '--tmpfs=/workspace:rw,noexec,nosuid,nodev,size=16m,mode=1777',
                    '--entrypoint=/usr/local/bin/python3', self._image_id,
                    '-I', '-B', '-c', FIXTURE, operation]
            code, out, _ = self._cli(args)
            if code: raise SafetyError('container creation refused')
            created = True
            container = out.decode('ascii').strip()
            if not re.fullmatch(r'[0-9a-f]{64}', container):
                raise SafetyError('valid created container ID required')
            obj = self._inspect_container(container)
            host, cfg = obj['HostConfig'], obj['Config']
            if not (host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] is True
                    and host['Privileged'] is False and host['CapDrop'] == ['ALL']
                    and not host.get('CapAdd') and not host.get('Binds')
                    and not host.get('Devices') and not host.get('DeviceRequests')
                    and host.get('PidMode', '') == '' and host.get('IpcMode') == 'private'
                    and cfg['User'] == '65534:65534'
                    and host['NanoCpus'] == int(limits.cpu * 1000000000)
                    and host['Memory'] == host['MemorySwap'] == limits.memory_bytes
                    and host['PidsLimit'] == limits.processes
                    and 'no-new-privileges:true' in host['SecurityOpt']
                    and not obj.get('Mounts')
                    and host['Tmpfs'] == {'/workspace': 'rw,noexec,nosuid,nodev,size=16m,mode=1777'}):
                raise SafetyError('effective container restrictions mismatch')
            self._check_image()
            self._inspect_container(container)
            status = 'completed'
            try:
                code, out, err = self._cli(['start', '--attach', container], timeout=limits.wall_seconds,
                                          caps=((limits.artifact_bytes + 65536) if operation == 'artifact-fixture' else limits.stdout_bytes, limits.stderr_bytes), cancellation=cancellation)
            except TimeoutError:
                status = 'canceled' if cancellation and cancellation.requested else 'timeout'
                self._cli(['stop', '--time', str(max(1, int(limits.grace_seconds))), container],
                          timeout=limits.grace_seconds + 3)
                code, out, err = None, b'', b''
            state = self._inspect_container(container)['State']
            if state['Running']: raise SafetyError('container still running')
            if status == 'completed': code = state['ExitCode']
            artifacts = ()
            if operation == 'artifact-fixture' and code == 0:
                artifacts = collect_artifacts(out, limits)
                out = b''
            return status, code, out, err, artifacts
        finally:
            # Even a failed create may have allocated the name. Removal is always
            # attempted; inability to confirm absence permanently poisons adapter.
            self._failed = True
            rc, _, _ = self._cli(['rm', '--force', name])
            check, remaining, _ = self._cli(['ps', '--all', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}'])
            if (created and rc) or check != 0 or remaining.strip():
                self._failed = True
                raise SafetyError('container cleanup unconfirmed')
            self._failed = False

    def conform(self):
        """Real disposable probes only; never persisted or inferred from inventory."""
        from .runtime import Cancellation, Limits
        from threading import Timer
        self._attested = False
        if self._failed:
            raise SafetyError('adapter poisoned by cleanup failure')
        self._check_daemon()
        limits = Limits(wall_seconds=3, grace_seconds=1)
        probe = self._run('probe', limits)
        resources = self._run('resource-fixture', limits)
        timeout = self._run('timeout-fixture', limits)
        if probe[:2] != ('completed', 0) or resources[:2] != ('completed', 0) or timeout[0] != 'timeout':
            raise SafetyError('live conformance failed')
        capture = self._run('capture-fixture', limits)
        artifact = self._run('artifact-fixture', limits)
        signal = Cancellation()
        timer = Timer(.5, signal.cancel)
        timer.start()
        try:
            canceled = self._run('cancel-fixture', limits, signal)
        finally:
            timer.cancel()
            timer.join()
        if (capture[1] != 0 or len(capture[2]) != limits.stdout_bytes
                or len(capture[3]) != limits.stderr_bytes
                or artifact[4] != (('result.txt', b'synthetic artifact\n'),)
                or canceled[0] != 'canceled' or self._failed):
            raise SafetyError('capture, artifact or cancellation conformance failed')
        self._attested = True

    def execute(self, request, cancellation):
        if not self._attested or self._failed:
            raise SafetyError('live conformance required')
        self._check_daemon()
        return self._run(request.operation, request.limits, cancellation)


def collect_artifacts(archive, limits):
    """No extraction, traversal, links, devices, duplicate names or unbounded reads."""
    result, total, names = [], 0, set()
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as tar:
        for member in tar:
            name = member.name
            if member.isdir() and name in ('.', './'): continue
            if (not member.isfile() or name.startswith('/') or '..' in name.split('/')
                    or name in names or len(result) >= limits.artifact_count
                    or member.size < 0 or total + member.size > limits.artifact_bytes):
                raise SafetyError('unsafe or oversized artifact')
            names.add(name)
            total += member.size
            result.append((name, tar.extractfile(member).read(member.size)))
    return tuple(result)
