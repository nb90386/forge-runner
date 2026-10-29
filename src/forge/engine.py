"""Private fixed-operation Engine transport. No registry, exec, mounts or fallback.

Only ContainerAdapter calls this module. Its vocabulary is runner-owned, never
forwarded from a job. HTTP connections are disposable and always Unix-local.
"""
import http.client
import inspect
import io
import json
import re
import select
import socket
import struct
import time
from urllib.parse import quote

from .safety import SafetyError, checked_path, identity, verify

NAME = r'forge-fixture-[0-9a-f]{32}'
ID = r'[0-9a-f]{64}'
DIGEST = r'sha256:[0-9a-f]{64}'
MARKER = b'forge-parent-and-child-started\n'


class _Reader(io.RawIOBase):
    def __init__(self, sock, deadline, cancellation):
        self.sock, self.deadline, self.cancellation = sock, deadline, cancellation

    def readable(self):
        return True

    def readinto(self, target):
        while True:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0 or self.cancellation and self.cancellation.requested:
                raise TimeoutError('container supervision interrupted')
            if select.select([self.sock], [], [], min(.05, remaining))[0]:
                return self.sock.recv_into(target)


class _Wire:
    def __init__(self, sock, deadline, cancellation):
        self.sock, self.deadline, self.cancellation = sock, deadline, cancellation

    def makefile(self, mode):
        return io.BufferedReader(_Reader(self.sock, self.deadline, self.cancellation))


class Engine:
    def __init__(self, endpoint):
        self.endpoint = endpoint

    def _request(self, method, path, body=None, *, deadline, cancellation=None, stream=False):
        # Defense in depth: even internal mistakes cannot address another API.
        routes = {
            'GET': (r'/info', r'/images/[^/?]+/json', r'/containers/' + ID + r'/json',
                    r'/containers/json\?all=1&filters=[^ ]+'),
            'POST': (r'/containers/create\?name=' + NAME,
                     r'/containers/' + ID + r'/attach\?stream=1&stdout=1&stderr=1',
                     r'/containers/' + ID + r'/start', r'/containers/' + ID + r'/stop\?t=[1-9][0-9]?'),
            'DELETE': (r'/containers/' + NAME + r'\?force=1&v=1',),
        }
        if (not any(re.fullmatch(pattern, path) for pattern in routes.get(method, ()))
                or body is not None and not path.startswith('/containers/create?name=')):
            raise SafetyError('engine operation refused')
        endpoint = checked_path(self.endpoint)
        if not endpoint.is_socket(): raise SafetyError('approved Unix socket required')
        if not hasattr(self, '_identity'): self._identity = identity(endpoint)
        verify(endpoint, self._identity)
        if body is not None:
            try:
                cmd = body['Cmd']
                name = path.split('=', 1)[1]
                args = ['create', '--pull=never', '--name', name, '--network=none', '--read-only',
                        '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--user=65534:65534',
                        '--cpus=' + cmd[-3], '--memory=' + cmd[-2], '--memory-swap=' + cmd[-2],
                        '--pids-limit=' + cmd[-1], '--ipc=private', '--cgroupns=host', '--log-driver=none',
                        '--tmpfs=/workspace:rw,noexec,nosuid,nodev,size=16m,mode=1777',
                        '--entrypoint=/usr/local/bin/python3', body['Image'], *cmd]
                if self._creation(args)[1] != body: raise ValueError()
            except (KeyError, TypeError, IndexError, ValueError) as exc:
                raise SafetyError('creation body refused') from exc
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        response = None
        handed_off = False
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or cancellation and cancellation.requested:
                raise TimeoutError('container supervision interrupted')
            sock.settimeout(remaining)
            sock.connect(self.endpoint)
            payload = b'' if body is None else json.dumps(body, separators=(',', ':'), allow_nan=False).encode()
            headers = (f'{method} /v1.45{path} HTTP/1.1\r\nHost: localhost\r\n'
                       f'Content-Length: {len(payload)}\r\nContent-Type: application/json\r\n' +
                       ('Connection: Upgrade\r\nUpgrade: tcp\r\n\r\n' if stream else
                        'Connection: close\r\n\r\n')).encode('ascii')
            sock.sendall(headers + payload)
            response = http.client.HTTPResponse(_Wire(sock, deadline, cancellation))
            response.begin()
            if stream:
                if (response.status != 101 or response.headers.get_all('Transfer-Encoding')
                        or response.headers.get_all('Content-Length') or
                        response.getheader('Upgrade', '').lower() != 'tcp' or
                        response.getheader('Connection', '').lower() != 'upgrade' or
                        response.getheader('Content-Type', '').split(';')[0] not in
                        ('application/vnd.docker.raw-stream', 'application/vnd.docker.multiplexed-stream')):
                    raise SafetyError('attach refused')
                handed_off = True
                return sock, response
            if response.status not in (200, 201, 204, 304, 404):
                raise SafetyError('engine request refused')
            # Ordinary API messages must have an explicit, unambiguous boundary.
            lengths = response.headers.get_all('Content-Length', [])
            transfers = response.headers.get_all('Transfer-Encoding', [])
            if (len(lengths) > 1 or transfers and (transfers != ['chunked'] or lengths)):
                raise SafetyError('ambiguous engine response')
            if response.status not in (204, 304) and not lengths and not transfers:
                raise SafetyError('unframed engine response')
            if lengths and (not lengths[0].isdigit() or int(lengths[0]) > 1048576):
                raise SafetyError('oversized engine response')
            if transfers:
                chunks = bytearray()
                while True:
                    line = response.fp.readline(128)
                    if not re.fullmatch(rb'[0-9a-fA-F]{1,8}\r\n', line):
                        raise SafetyError('invalid HTTP chunk')
                    size = int(line[:-2], 16)
                    if size == 0:
                        if response.fp.read(2) != b'\r\n':
                            raise SafetyError('incomplete HTTP terminator')
                        break
                    if size + len(chunks) > 1048576:
                        raise SafetyError('oversized engine response')
                    chunk = response.fp.read(size)
                    if len(chunk) != size or response.fp.read(2) != b'\r\n':
                        raise SafetyError('incomplete HTTP chunk')
                    chunks.extend(chunk)
                data = bytes(chunks)
            else:
                data = response.read(1048577)
            if len(data) > 1048576: raise SafetyError('oversized engine response')
            if lengths and len(data) != int(lengths[0]):
                raise SafetyError('incomplete engine response')
            return response.status, data
        except TimeoutError:
            raise
        except (OSError, ValueError, http.client.HTTPException) as exc:
            raise SafetyError('engine connection failed') from exc
        finally:
            if not handed_off:
                try:
                    if response is not None: response.close()
                finally:
                    sock.close()

    def operation(self, args, *, timeout=10, caps=(1048576, 1048576), cancellation=None, on_started=None):
        deadline = time.monotonic() + timeout
        def request(method, path, body=None):
            return self._request(method, path, body, deadline=deadline, cancellation=cancellation)
        def document(method, path, body=None, expected=200):
            status, data = request(method, path, body)
            if status != expected: raise SafetyError('engine response refused')
            try:
                def pairs(items):
                    result = {}
                    for key, value in items:
                        if key in result: raise ValueError('duplicate key')
                        result[key] = value
                    return result
                return json.loads(data, object_pairs_hook=pairs,
                                  parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            except (ValueError, UnicodeError) as exc:
                raise SafetyError('invalid engine JSON') from exc
        if args == ['info', '--format', '{{json .}}']:
            result = document('GET', '/info')
        elif len(args) == 3 and args[:2] == ['image', 'inspect']:
            if not re.fullmatch(r'[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}', args[2]):
                raise SafetyError('immutable image required')
            result = [document('GET', '/images/' + quote(args[2], safe='') + '/json')]
        elif len(args) == 2 and args[0] == 'inspect' and re.fullmatch(ID, args[1]):
            result = [document('GET', '/containers/' + args[1] + '/json')]
        elif args and args[0] == 'create':
            name, body = self._creation(args)
            result = document('POST', '/containers/create?name=' + name, body, 201)
            if (type(result) is not dict or not re.fullmatch(ID, result.get('Id', ''))
                    or result.get('Warnings') not in (None, [])):
                raise SafetyError('ambiguous creation response')
            return 0, result['Id'].encode(), b''
        elif len(args) == 3 and args[:2] == ['start', '--attach'] and re.fullmatch(ID, args[2]):
            return self._attached(args[2], deadline, caps, cancellation, on_started)
        elif (len(args) == 4 and args[:2] == ['stop', '--time']
              and re.fullmatch(r'[1-9][0-9]?', args[2]) and re.fullmatch(ID, args[3])):
            status, data = request('POST', '/containers/' + args[3] + '/stop?t=' + args[2])
            if status != 204 or data: raise SafetyError('stop unconfirmed')
            return 0, b'', b''
        elif len(args) == 3 and args[:2] == ['rm', '--force'] and re.fullmatch(NAME, args[2]):
            status, data = request('DELETE', '/containers/' + args[2] + '?force=1&v=1')
            if status not in (204, 404): raise SafetyError('removal refused')
            return (0 if status == 204 else 1), b'', b''
        elif (len(args) == 6 and args[:3] == ['ps', '--all', '--filter']
              and args[4:] == ['--format', '{{.Names}}']
              and re.fullmatch(r'name=\^/' + NAME + r'\$', args[3])):
            filters = quote(json.dumps({'name': [args[3][5:]]}, separators=(',', ':')), safe='')
            result = document('GET', '/containers/json?all=1&filters=' + filters)
            if type(result) is not list: raise SafetyError('ambiguous absence response')
            return 0, b'' if result == [] else b'present', b''
        else:
            raise SafetyError('engine operation refused')
        return 0, json.dumps(result, allow_nan=False).encode(), b''

    @staticmethod
    def _creation(args):
        from .container import FIXTURE, cgroup_membership, verify_cgroups
        from .runtime import Limits
        try:
            name = args[3]
            cpu, memory, pids = args[-3:]
            limits = Limits(cpu=float(cpu), memory_bytes=int(memory), processes=int(pids))
            limits.validate()
            image, operation = args[-9], args[-4]
            script = inspect.getsource(cgroup_membership) + inspect.getsource(verify_cgroups) + FIXTURE
            expected = ['create', '--pull=never', '--name', name, '--network=none', '--read-only',
                        '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--user=65534:65534',
                        '--cpus=' + cpu, '--memory=' + memory, '--memory-swap=' + memory,
                        '--pids-limit=' + pids, '--ipc=private', '--cgroupns=host', '--log-driver=none',
                        '--tmpfs=/workspace:rw,noexec,nosuid,nodev,size=16m,mode=1777',
                        '--entrypoint=/usr/local/bin/python3', image, '-I', '-B', '-c', script,
                        operation, cpu, memory, pids]
            if (args != expected or not re.fullmatch(NAME, name) or not re.fullmatch(DIGEST, image)
                    or operation not in ('probe', 'resource-fixture', 'timeout-fixture', 'cancel-fixture',
                                         'capture-fixture', 'artifact-fixture')):
                raise ValueError()
        except (ValueError, TypeError, IndexError) as exc:
            raise SafetyError('fixed creation required') from exc
        host = dict(NetworkMode='none', ReadonlyRootfs=True, Privileged=False, CapDrop=['ALL'],
                    SecurityOpt=['no-new-privileges:true'], NanoCpus=int(limits.cpu * 1000000000),
                    Memory=limits.memory_bytes, MemorySwap=limits.memory_bytes, PidsLimit=limits.processes,
                    IpcMode='private', CgroupnsMode='host', LogConfig={'Type': 'none', 'Config': {}},
                    Tmpfs={'/workspace': 'rw,noexec,nosuid,nodev,size=16m,mode=1777'})
        return name, dict(Image=image, User='65534:65534', Entrypoint=['/usr/local/bin/python3'],
                          Cmd=['-I', '-B', '-c', script, operation, cpu, memory, pids],
                          AttachStdout=True, AttachStderr=True, Tty=False, OpenStdin=False,
                          Healthcheck={'Test': ['NONE']}, StopSignal='SIGTERM',
                          NetworkDisabled=True, HostConfig=host)

    def _attached(self, container, deadline, caps, cancellation, on_started):
        sock = response = None
        try:
            sock, response = self._request('POST', '/containers/' + container +
                                          '/attach?stream=1&stdout=1&stderr=1',
                                          deadline=deadline, cancellation=cancellation, stream=True)
            status, data = self._request('POST', '/containers/' + container + '/start',
                                         deadline=deadline, cancellation=cancellation)
            if status != 204 or data: raise SafetyError('start refused')
            output = [bytearray(), bytearray()]
            evidence = bytearray()
            announced = False
            def exact(size, eof=False):
                buf = bytearray()
                while len(buf) < size:
                    if time.monotonic() >= deadline or cancellation and cancellation.requested:
                        raise TimeoutError('container supervision interrupted')
                    chunk = response.fp.read1(min(16384, size - len(buf)))
                    if not chunk:
                        if eof and not buf: return b''
                        raise SafetyError('truncated Docker frame')
                    buf.extend(chunk)
                return bytes(buf)
            while True:
                header = exact(8, True)
                if not header: break
                stream, reserved, size = header[0], header[1:4], struct.unpack('>I', header[4:])[0]
                if stream not in (1, 2) or reserved != b'\0\0\0' or size > 16777216:
                    raise SafetyError('invalid Docker frame')
                while size:
                    chunk = exact(min(size, 16384))
                    size -= len(chunk)
                    target = output[stream - 1]
                    target.extend(chunk[:max(0, caps[stream - 1] - len(target))])
                    if on_started:
                        if stream != 1 or len(evidence) + len(chunk) > len(MARKER):
                            raise SafetyError('unexpected startup evidence')
                        evidence.extend(chunk)
                        if not MARKER.startswith(evidence): raise SafetyError('malformed startup evidence')
                        if evidence == MARKER and not announced:
                            on_started()
                            announced = True
            if on_started: raise SafetyError('startup fixture unexpectedly closed')
            return 0, bytes(output[0]), bytes(output[1])
        except TimeoutError:
            raise
        except (OSError, ValueError, http.client.HTTPException) as exc:
            raise SafetyError('attached connection failed') from exc
        finally:
            try:
                if response is not None: response.close()
            finally:
                if sock is not None: sock.close()
