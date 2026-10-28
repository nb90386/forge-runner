"""0.6E loopback lease bookkeeping. No credential discovery or agent launcher.

The watchdog is independent of the caller and transport locks, but is not an OS
isolation boundary. Real execution remains forbidden, including after cleanup.
"""
import http.client
import json
import math
import os
import re
import signal
import socket
import threading
import time

from .dispatch import LoopbackTransport
from .lease import LeaseWorker, MockSupervisor, refuse
from .safety import SafetyError, task_id

PUBLIC = {'job_id', 'approval_id', 'project_id', 'repository_identity', 'commit_sha',
          'envelope_digest', 'worker_id', 'state', 'generation', 'expires_at',
          'created_at', 'updated_at', 'heartbeat_at', 'acknowledged_at'}
ACTIONS = ('claim', 'acknowledge', 'heartbeat', 'renew', 'finish')


class SystemClock:
    @property
    def wall(self):
        return time.time()

    @property
    def monotonic(self):
        return time.monotonic()


def number(value):
    return type(value) in (int, float) and math.isfinite(value)


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            refuse()
        result[key] = value
    return result


class HTTPLeaseTransport:
    """One attempt, numeric loopback, no proxies/redirects; total I/O deadline.

    The injected provider supplies a dedicated execution secret, never a filename
    or environment variable. The caller must authenticate the local listener.
    """
    def __init__(self, origin, secret_provider, *, timeout=2):
        address = LoopbackTransport(origin)
        if not number(timeout) or not 0 < timeout <= 5 or not callable(secret_provider):
            refuse()
        self.host, self.port = address.host, address.port
        # Configuration-time injection only: request deadlines never depend on
        # arbitrary provider I/O. Rotation requires a new transport/worker.
        try:
            secret = secret_provider()
            if type(secret) is not str or not 32 <= len(secret) <= 4096 or not all(33 <= ord(c) <= 126 for c in secret):
                refuse()
        except Exception:
            raise SafetyError('lease: execution credential unavailable') from None
        self._secret, self.timeout = secret, timeout

    def request(self, action, data, worker):
        sock = None
        connection = None
        timer = None
        try:
            task_id(worker)
            fields = ({'job_id', 'approval_id', 'repository_identity', 'commit_sha',
                       'envelope_digest', 'idempotency_key'} if action == 'claim'
                      else {'job_id', 'generation', 'lease_credential'})
            if action == 'finish':
                fields |= {'state'}
            if action not in ACTIONS or type(data) is not dict or set(data) != fields:
                refuse()
            if any(type(data[k]) is not str or not 1 <= len(data[k]) <= 200
                   for k in fields - {'generation'}):
                refuse()
            if action != 'claim' and (type(data['generation']) is not int
                                      or not 1 <= data['generation'] <= 9223372036854775807):
                refuse()
            if action == 'finish' and data['state'] not in ('completed', 'failed', 'canceled'):
                refuse()
            body = json.dumps(data, allow_nan=False, separators=(',', ':')).encode()
            if len(body) > 4096:
                refuse()
            secret = self._secret
            if type(secret) is not str or not 32 <= len(secret) <= 4096 or not all(33 <= ord(c) <= 126 for c in secret):
                refuse()
            sock = socket.socket(socket.AF_INET6 if self.host == '::1' else socket.AF_INET,
                                 socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            # shutdown interrupts slow-drip headers/body as well as blocked writes.
            def interrupt():
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            timer = threading.Timer(self.timeout, interrupt)
            timer.daemon = True
            start = time.monotonic()
            timer.start()
            sock.connect((self.host, self.port))
            if sock.getpeername()[:2] != (self.host, self.port):
                refuse()
            connection = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
            connection.sock = sock
            connection.request('POST', '/api/worker/execution/' + action, body=body,
                               headers={'Authorization': 'Bearer ' + secret,
                                        'X-Forge-Worker-ID': worker, 'Content-Type': 'application/json',
                                        'Accept': 'application/json', 'Connection': 'close'})
            response = connection.getresponse()
            headers = response.getheaders()
            def values(name):
                return [v for k, v in headers if k.lower() == name]
            lengths = values('content-length')
            if (response.status != 200 or values('transfer-encoding')
                    or values('content-encoding') not in ([], ['identity'])
                    or values('cache-control') != ['no-store']
                    or values('content-type') not in (['application/json'], ['application/json; charset=utf-8'])
                    or len(lengths) != 1 or not re.fullmatch(r'[0-9]{1,5}', lengths[0])
                    or not 0 < int(lengths[0]) <= 4096):
                refuse()
            raw = response.read(int(lengths[0]) + 1)
            if len(raw) != int(lengths[0]) or time.monotonic() - start >= self.timeout:
                refuse()
            result = json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                                parse_constant=lambda _: refuse())
            validate_response(result, action)
            return result
        except Exception:
            raise SafetyError('lease: HTTP operation uncertain; reconciliation required') from None
        finally:
            if timer:
                timer.cancel()
            if connection:
                connection.close()
            if sock:
                sock.close()


def validate_response(row, action):
    fields = PUBLIC | ({'lease_credential'} if action in ('claim', 'renew') else set())
    if type(row) is not dict or set(row) != fields:
        refuse()
    for key in ('job_id', 'approval_id', 'project_id', 'worker_id'):
        task_id(row[key])
    if (type(row['generation']) is not int or not 1 <= row['generation'] <= 9223372036854775807
            or row['state'] not in ('claimed', 'running', 'completed', 'failed', 'canceled')
            or any(not number(row[k]) for k in ('expires_at', 'created_at', 'updated_at'))
            or not row['created_at'] <= row['updated_at'] < row['expires_at']
            or row['expires_at'] - row['updated_at'] > 60):
        refuse()
    for key in ('heartbeat_at', 'acknowledged_at'):
        if row[key] is not None and (not number(row[key])
                or not row['created_at'] <= row[key] <= row['updated_at']):
            refuse()
    if row['state'] == 'claimed':
        if row['heartbeat_at'] is not None or row['acknowledged_at'] is not None:
            refuse()
    elif (row['heartbeat_at'] is None or row['acknowledged_at'] is None
          or row['heartbeat_at'] < row['acknowledged_at']):
        refuse()
    if 'lease_credential' in row and (type(row['lease_credential']) is not str
            or not re.fullmatch(r'[0-9a-f]{64}', row['lease_credential'])):
        refuse()


class ProcessGroupCancellation:
    """Best-effort TERM/KILL for an externally owned group; never attests isolation.

    No launch or automatic PID discovery. Escaped descendants cannot be proven
    absent with portable POSIX APIs, so even an empty group is not a tree guarantee.
    """
    def __init__(self, pgid):
        if type(pgid) is not int or pgid <= 1 or pgid == os.getpgrp():
            refuse()
        self.pgid = pgid

    def terminate(self):
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(self.pgid, sig)
            except ProcessLookupError:
                break
        raise SafetyError('lease: process-tree containment unproven; cleanup uncertain')


class LeaseWatchdog:
    """Trusted deadline lane, independent of worker/registry/network locks."""
    def __init__(self, worker, interval):
        self.worker, self.interval = worker, interval
        self.closed = threading.Event()
        self.thread = threading.Thread(target=self.run, name='forge-lease-watchdog', daemon=True)
        self.thread.start()

    def run(self):
        while not self.closed.wait(self.interval):
            w = self.worker
            with w._authority_lock:
                deadline = w._deadline
                expired = deadline is not None and (w.clock.monotonic >= deadline
                                                    or w.supervisor.cancellation.requested)
                if expired:
                    w._stop()  # terminate before persistence or acquiring worker lock
            if expired:
                try:
                    w._save('blocked', w._metadata['generation'] if w._metadata else 0)
                except Exception:
                    pass  # existing intent is already a durable fence
                return

    def close(self):
        self.closed.set()
        self.thread.join(timeout=1)


class HTTPLeaseWorker(LeaseWorker):
    """Lease integration only; synthetic supervisor is the sole accepted boundary."""
    def __init__(self, registry, transport, worker_id, *, poll_interval=.25):
        if (type(transport) is not HTTPLeaseTransport or type(poll_interval) not in (int, float)
                or not math.isfinite(poll_interval) or not .01 <= poll_interval <= 1):
            refuse()
        task_id(worker_id)
        self.registry, self.transport, self.worker_id = registry, transport, worker_id
        self.clock, self.supervisor = SystemClock(), MockSupervisor()
        self._lock = threading.RLock()
        self._authority_lock = threading.RLock()
        self._permit = self._deadline = self._job = self._approval_deadline = None
        self._metadata = None
        self._closed = threading.Event()
        self._reconcile()
        self.watchdog = LeaseWatchdog(self, min(poll_interval, .05))
        self._poller = threading.Thread(target=self._poll, args=(poll_interval,),
                                        name='forge-lease-poller', daemon=True)
        self._poller.start()

    def _reconcile(self):
        try:
            with self.registry.locked(write=True) as data:
                records = data.setdefault('lease_records', {})
                if type(records) is not dict or any(type(r) is not dict for r in records.values()):
                    refuse()
                for row in records.values():
                    if row.get('state') not in ('completed', 'failed', 'canceled', 'expired'):
                        row['state'] = 'blocked'
        except Exception:
            raise SafetyError('lease: durable reconciliation unavailable') from None

    def _request(self, action, payload):
        # Pending claims also have a deadline. The watchdog never waits for I/O.
        if action == 'claim':
            self._deadline = min(self.clock.monotonic + self.transport.timeout,
                                 self._approval_deadline)
        return super()._request(action, payload)

    def _validate_response(self, response, action):
        validate_response(response, action)
        previous = self._metadata
        if (self.supervisor.terminated or response["updated_at"] > self.clock.wall
                or response["expires_at"] > self.clock.wall + 60):
            refuse()
        if previous is not None:
            if (response["created_at"] != previous["created_at"]
                    or response["updated_at"] < previous["updated_at"]
                    or (previous["acknowledged_at"] is not None
                        and response["acknowledged_at"] != previous["acknowledged_at"])
                    or (action == "renew" and response["lease_credential"] == self._permit["lease_credential"])):
                refuse()
        if action == 'claim' and response['created_at'] != response['updated_at']:
            refuse()
        if action in ('heartbeat', 'acknowledge') and response['heartbeat_at'] != response['updated_at']:
            refuse()
        if previous is not None and action in ('renew', 'finish'):
            if (response['heartbeat_at'] != previous['heartbeat_at']
                    or response['acknowledged_at'] != previous['acknowledged_at']):
                refuse()
        self._metadata = dict(response)

    def _save(self, state, generation):
        if self.supervisor.terminated and state != 'blocked':
            refuse()
        try:
            with self.registry.locked(write=True) as data:
                row = data['lease_records'][self._job['job_id']]
                if row['state'] == 'blocked' and state != 'blocked':
                    refuse()
                # Never lose a known fencing generation during reconciliation.
                row.update(state=state, generation=max(row['generation'], generation))
        except Exception:
            raise SafetyError('lease: durable update unavailable') from None

    def _poll(self, interval):
        while not self._closed.wait(interval):
            if self._permit is not None:
                try:
                    self.step('heartbeat' if self._permit['state'] == 'running' else 'renew')
                except Exception:
                    return

    def manifest(self):
        return {**super().manifest(), 'adapter': 'forge-0.6E', 'transport': 'loopback-http',
                'process_tree_guarantee': False}

    def close(self):
        self._closed.set()
        self._stop()
        self.watchdog.close()
        self._poller.join(timeout=self.transport.timeout + 1)
        if self._job is not None and self._metadata is not None and self._metadata['state'] not in ('completed', 'failed', 'canceled'):
            try:
                self._save('blocked', self._metadata['generation'])
            except Exception:
                pass
