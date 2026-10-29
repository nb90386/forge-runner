"""Docker-compatible synthetic sandbox. No repository code or host mounts.

Conformance is deliberately process-local and must be earned against the daemon.
The operator supplies an audited, locally provisioned Python image by digest.
"""
from dataclasses import dataclass
import io
import inspect
import json
import os
import re
import tarfile
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


def cgroup_membership(read):
    """Resolve an unescaped, complete host v2 hierarchy; fail on hidden ancestry."""
    def path(value):
        if (not value.startswith('/') or '\\' in value or
                any(c.isspace() or ord(c) < 32 for c in value) or
                value != '/' and any(p in ('', '.', '..') for p in value[1:].split('/'))):
            raise ValueError('invalid cgroup path')
        return value
    membership = read('/proc/self/cgroup').splitlines()
    if len(membership) != 1 or not membership[0].startswith('0::/'):
        raise ValueError('ambiguous cgroup membership')
    member = path(membership[0][3:])
    mountinfo = read('/proc/self/mountinfo')
    mounts = []
    for line in mountinfo.splitlines():
        fields = line.split()
        if ' - cgroup2 ' not in line:
            continue
        if fields.count('-') != 1:
            raise ValueError('invalid mount evidence')
        split = fields.index('-')
        if split < 6 or len(fields) != split + 4:
            raise ValueError('invalid mount evidence')
        root, mount = path(fields[3]), path(fields[4])
        if root != '/' or mount == '/':
            raise ValueError('complete cgroup ancestry required')
        mounts.append(mount)
    if len(mounts) != 1 or member == '/':
        raise ValueError('unique nonroot membership required')
    mount = mounts[0]
    # An overmount could make reads refer to an unrelated filesystem.
    for line in mountinfo.splitlines():
        fields = line.split()
        if len(fields) < 6:
            raise ValueError('invalid mount evidence')
        other = path(fields[4])
        if other.startswith(mount + '/') or other == mount and ' - cgroup2 ' not in line:
            raise ValueError('obscured cgroup evidence')
    if (read('/proc/self/cgroup').splitlines() != membership or
            read('/proc/self/mountinfo') != mountinfo):
        raise ValueError('changed cgroup membership')
    return mount, member


def verify_cgroups(cpu, memory, pids, read):
    """Evaluate limits from membership through every nonroot ancestor."""
    from fractions import Fraction
    mount, path = cgroup_membership(read)
    original = mount, path
    effective = [None, None, None]
    while path != '/':
        base = mount + path
        for index, name in enumerate(('cpu.max', 'memory.max', 'pids.max')):
            fields = read(base + '/' + name).split()
            if index == 0:
                if len(fields) != 2 or not fields[1].isdigit() or int(fields[1]) <= 0:
                    raise ValueError('invalid cpu evidence')
                denominator = int(fields[1])
            else:
                if len(fields) != 1: raise ValueError('invalid limit evidence')
                denominator = 1
            if fields[0] == 'max': continue
            if not fields[0].isdigit() or int(fields[0]) <= 0:
                raise ValueError('invalid limit evidence')
            value = Fraction(int(fields[0]), denominator)
            effective[index] = value if effective[index] is None else min(value, effective[index])
        path = path.rsplit('/', 1)[0] or '/'
    if cgroup_membership(read) != original:
        raise ValueError('changed cgroup evidence')
    if any(value is None or value > requested for value, requested in
           zip(effective, (Fraction(str(cpu)), memory, pids))):
        raise ValueError('effective cgroup limits too weak')


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
    verify_cgroups(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]),
                   lambda path: open(path).read())
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
    reader, writer = os.pipe()
    if os.fork() == 0:
        os.close(reader)
        os.write(writer, b'child-started')
        os.close(writer)
        while True: time.sleep(1)
    os.close(writer)
    assert os.read(reader, 64) == b'child-started'
    os.close(reader)
    print('forge-parent-and-child-started', flush=True)
    while True: time.sleep(1)
elif op == 'resource-fixture':
    import errno, signal
    def event(controller, key):
        assert cgroup_membership(lambda path: open(path).read()) == (mount, member)
        with open(base + '/' + controller + '.events') as stream:
            return dict(line.split() for line in stream)[key]
    mount, member = cgroup_membership(lambda path: open(path).read())
    base = mount + member
    pids_max = int(open(base + '/pids.max').read())
    assert 0 < pids_max <= 256
    before = int(event('pids', 'max'))
    children = []
    try:
        # Bound the probe even if enforcement is broken.
        for _ in range(pids_max):
            try:
                pid = os.fork()
            except OSError as exc:
                assert exc.errno == errno.EAGAIN
                assert int(event('pids', 'max')) > before
                break
            if pid == 0: time.sleep(60); os._exit(0)
            children.append(pid)
        else: raise AssertionError('pids unbounded')
    finally:
        for pid in children: os.kill(pid, 9); os.waitpid(pid, 0)
    memory_max = int(open(base + '/memory.max').read())
    assert 0 < memory_max <= 2147483648
    before_max = int(event('memory', 'max'))
    before_oom = int(event('memory', 'oom_kill'))
    pid = os.fork()
    if pid == 0:
        try:
            a = bytearray(memory_max * 2)
        except MemoryError:
            os._exit(42)
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    # A cgroup limit commonly kills the allocating child rather than returning
    # ENOMEM to Python. Neither SIGKILL nor MemoryError alone proves enforcement.
    assert int(event('memory', 'max')) > before_max
    assert (os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
            and int(event('memory', 'oom_kill')) > before_oom
            or os.WIFEXITED(status) and os.WEXITSTATUS(status) == 42)

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
        self._diagnostic = None

    def diagnostic(self):
        """Only allowlisted runner-owned codes cross the reporting boundary."""
        value = self._diagnostic
        if (type(value) is tuple and len(value) == 3
                and all(type(part) is str for part in value)
                and value[0] in ('daemon', 'probe', 'resource-fixture', 'timeout-fixture',
                                 'capture-fixture', 'artifact-fixture', 'cancel-fixture')
                and value[1] in ('daemon_check', 'image_check', 'create', 'create_id',
                                 'restrictions', 'identity_recheck', 'start', 'stop',
                                 'exit_state', 'artifacts', 'result', 'cleanup_remove',
                                 'cleanup_confirm')
                and value[2] in ('refused', 'interrupted', 'result_mismatch')):
            return dict(probe=value[0], stage=value[1], code=value[2])
        return dict(probe='unknown', stage='unknown', code='refused')

    def _cli(self, args, *, timeout=10, caps=(1048576, 1048576), cancellation=None, on_started=None):
        """Legacy internal operation vocabulary; never executes a host command."""
        from .engine import Engine
        if not hasattr(self, '_engine'):
            self._engine = Engine(self.config.socket)
        return self._engine.operation(args, timeout=timeout, caps=caps,
                                cancellation=cancellation, on_started=on_started)

    def _json(self, args, *, timeout=10):
        code, out, _ = self._cli(args, timeout=timeout)
        if code: raise SafetyError('container engine refused')
        return json.loads(out)

    def _check_daemon(self):
        info = self._json(['info', '--format', '{{json .}}'])
        if (info.get('OSType') != 'linux' or not info.get('ID')
                or type(info.get('ID')) is not str
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

    def _inspect_container(self, container, *, timeout=10):
        obj, = self._json(['inspect', container], timeout=timeout)
        if (obj.get('Id') != container or obj.get('Image') != self._image_id
                or obj.get('Config', {}).get('Image') != self._image_id):
            raise SafetyError('created container image identity mismatch')
        return obj

    @staticmethod
    def _timestamp(value):
        from datetime import datetime
        if (type(value) is not str or re.fullmatch(
                r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z', value)
                is None or value.startswith('0001-')):
            return False
        try:
            datetime.strptime(value[:19], '%Y-%m-%dT%H:%M:%S')
            return True
        except ValueError:
            return False

    def _run(self, operation, limits, cancellation=None):
        if self._failed:
            raise SafetyError('adapter poisoned by cleanup failure')
        if operation == 'noop': operation = 'probe'
        limits.validate()
        if operation not in ('probe', 'resource-fixture', 'timeout-fixture', 'cancel-fixture',
                             'capture-fixture', 'artifact-fixture'):
            raise SafetyError('fixed synthetic operation required')
        name = 'forge-fixture-' + uuid.uuid4().hex
        created = False
        container = name
        stage = 'image_check'
        try:
            self._check_image()
            args = ['create', '--pull=never', '--name', name, '--network=none', '--read-only',
                    '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--user=65534:65534',
                    '--cpus=' + str(limits.cpu), '--memory=' + str(limits.memory_bytes),
                    '--memory-swap=' + str(limits.memory_bytes), '--pids-limit=' + str(limits.processes),
                    '--ipc=private', '--cgroupns=host', '--log-driver=none', '--tmpfs=/workspace:rw,noexec,nosuid,nodev,size=16m,mode=1777',
                    '--entrypoint=/usr/local/bin/python3', self._image_id,
                    '-I', '-B', '-c', inspect.getsource(cgroup_membership) + inspect.getsource(verify_cgroups) + FIXTURE,
                    operation, str(limits.cpu), str(limits.memory_bytes), str(limits.processes)]
            stage = 'create'
            code, out, _ = self._cli(args)
            if code: raise SafetyError('container creation refused')
            created = True
            stage = 'create_id'
            container = out.decode('ascii').strip()
            if not re.fullmatch(r'[0-9a-f]{64}', container):
                raise SafetyError('valid created container ID required')
            stage = 'restrictions'
            obj = self._inspect_container(container)
            host, cfg = obj['HostConfig'], obj['Config']
            if not (host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] is True
                    and host['Privileged'] is False and host['CapDrop'] == ['ALL']
                    and not host.get('CapAdd') and not host.get('Binds')
                    and not host.get('Devices') and not host.get('DeviceRequests')
                    and host.get('CgroupnsMode') == 'host'
                    and host.get('PidMode', '') == '' and host.get('IpcMode') == 'private'
                    and cfg['User'] == '65534:65534'
                    and host['NanoCpus'] == int(limits.cpu * 1000000000)
                    and host['Memory'] == host['MemorySwap'] == limits.memory_bytes
                    and host['PidsLimit'] == limits.processes
                    and 'no-new-privileges:true' in host['SecurityOpt']
                    and not obj.get('Mounts')
                    and host['Tmpfs'] == {'/workspace': 'rw,noexec,nosuid,nodev,size=16m,mode=1777'}):
                raise SafetyError('effective container restrictions mismatch')
            stage = 'identity_recheck'
            self._check_image()
            self._inspect_container(container)
            status = 'completed'
            started = False
            run_deadline = time.monotonic() + limits.wall_seconds
            def startup():
                nonlocal started
                if cancellation and cancellation.requested:
                    raise SafetyError('pre-start cancellation')
                remaining = run_deadline - time.monotonic()
                if remaining <= 0: raise SafetyError('startup deadline elapsed')
                state = self._inspect_container(container, timeout=remaining)['State']
                if time.monotonic() >= run_deadline:
                    raise SafetyError('startup deadline elapsed')
                if (state.get('Running') is not True or type(state.get('Pid')) is not int
                        or state['Pid'] <= 0 or state.get('Status') != 'running'
                        or not self._timestamp(state.get('StartedAt'))):
                    raise SafetyError('startup unconfirmed')
                started = True
                if cancellation: cancellation.cancel()
            try:
                stage = 'start'
                code, out, err = self._cli(['start', '--attach', container], timeout=limits.wall_seconds,
                                          caps=((limits.artifact_bytes + 65536) if operation == 'artifact-fixture' else limits.stdout_bytes, limits.stderr_bytes), cancellation=cancellation,
                                          on_started=startup if operation in ('timeout-fixture', 'cancel-fixture') else None)
            except TimeoutError:
                status = 'canceled' if cancellation and cancellation.requested else 'timeout'
                stage = 'stop'
                self._cli(['stop', '--time', str(max(1, int(limits.grace_seconds))), container],
                          timeout=limits.grace_seconds + 3)
                if operation in ('timeout-fixture', 'cancel-fixture') and not started:
                    raise SafetyError('startup evidence missing')
                code, out, err = None, b'', b''
            stage = 'exit_state'
            state = self._inspect_container(container)['State']
            if (state.get('Running') is not False or state.get('Dead', False) is not False
                    or type(state.get('Pid')) is not int or state['Pid'] != 0
                    or type(state.get('ExitCode')) is not int
                    or state.get('Status') != 'exited'
                    or not self._timestamp(state.get('StartedAt'))
                    or not self._timestamp(state.get('FinishedAt'))):
                raise SafetyError('container termination unconfirmed')
            if status == 'completed': code = state['ExitCode']
            artifacts = ()
            if operation == 'artifact-fixture' and code == 0:
                stage = 'artifacts'
                artifacts = collect_artifacts(out, limits)
                out = b''
            return status, code, out, err, artifacts
        except (Exception, KeyboardInterrupt) as exc:
            self._diagnostic = (operation, stage,
                                'interrupted' if isinstance(exc, KeyboardInterrupt) else 'refused')
            raise
        finally:
            # Even a failed create may have allocated the name. Removal is always
            # attempted; inability to confirm absence permanently poisons adapter.
            stage = 'cleanup_remove'
            try:
                rc, _, _ = self._cli(['rm', '--force', name])
                stage = 'cleanup_confirm'
                check, remaining, _ = self._cli(['ps', '--all', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}'])
                if (created and rc) or check != 0 or remaining.strip():
                    if created and rc:
                        stage = 'cleanup_remove'
                    raise SafetyError('container cleanup unconfirmed')
            except BaseException as exc:
                # Any interrupted teardown leaves absence unconfirmed, including
                # SystemExit. Preserve the interruption after recording poison.
                self._failed = True
                self._diagnostic = (operation, stage,
                                    'interrupted' if not isinstance(exc, Exception) else 'refused')
                raise

    def conform(self):
        """Real disposable probes only; never persisted or inferred from inventory."""
        from .runtime import Cancellation, Limits
        self._attested = False
        if self._failed:
            raise SafetyError('adapter poisoned by cleanup failure')
        self._diagnostic = ('daemon', 'daemon_check', 'refused')
        self._check_daemon()
        limits = Limits(wall_seconds=3, grace_seconds=1)

        def check(operation, valid, cancellation=None):
            self._diagnostic = (operation, 'start', 'refused')
            result = self._run(operation, limits, cancellation)
            self._diagnostic = (operation, 'result', 'result_mismatch')
            if not valid(result) or self._failed:
                raise SafetyError('live conformance failed')

        check('probe', lambda r: r[:2] == ('completed', 0))
        check('resource-fixture', lambda r: r[:2] == ('completed', 0))
        check('timeout-fixture', lambda r: r[0] == 'timeout')
        check('capture-fixture', lambda r: r[1] == 0 and len(r[2]) == limits.stdout_bytes
              and len(r[3]) == limits.stderr_bytes)
        check('artifact-fixture', lambda r: r[4] == (('result.txt', b'synthetic artifact\n'),))
        signal = Cancellation()
        check('cancel-fixture', lambda r: r[0] == 'canceled', signal)
        self._diagnostic = None
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
