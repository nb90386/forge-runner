"""Offline protocol and allowlist regressions. Never contact a daemon."""
import io
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from forge.engine import Engine, MARKER, _Reader
from forge.container import ContainerAdapter, ContainerConfig
from forge.runtime import Limits, Cancellation
from forge.safety import SafetyError

CID = 'c' * 64
IID = 'sha256:' + 'a' * 64
REF = 'fixture@sha256:' + 'b' * 64


def frame(data, stream=1):
    return bytes([stream, 0, 0, 0]) + struct.pack('>I', len(data)) + data


class EngineTests(unittest.TestCase):
    def attached(self, data, callback=None, caps=(8, 8), error=None, cancellation=None):
        engine = Engine('/unused')
        response, sock = Mock(), Mock()
        response.fp = io.BufferedReader(io.BytesIO(data), buffer_size=8)
        if error: response.fp = Mock(read1=Mock(side_effect=error))
        with patch.object(engine, '_request', side_effect=[(sock, response), (204, b'')]):
            try:
                return engine.operation(['start', '--attach', CID], caps=caps,
                                        on_started=callback, cancellation=cancellation)
            finally:
                response.close.assert_called_once()
                sock.close.assert_called_once()

    def test_bounded_multiplexed_capture_and_fragmentation(self):
        result = self.attached(frame(b'x' * 200000) + frame(b'y' * 200000, 2))
        self.assertEqual(result, (0, b'x' * 8, b'y' * 8))
        self.assertEqual(self.attached(frame(b'abc') + frame(b'd', 2), caps=(0, 0)), (0, b'', b''))

    def test_malformed_truncated_and_oversized_frames(self):
        for data in (b'\1', frame(b'abc')[:-1], frame(b'abc', 0), frame(b'abc', 3),
                     b'\1\1\0\0\0\0\0\0', b'\1\0\0\0\xff\xff\xff\xff'):
            with self.subTest(data=data), self.assertRaises(SafetyError): self.attached(data)

    def test_complete_startup_marker_requires_state_callback(self):
        for data in (frame(MARKER), frame(MARKER[:7]) + frame(MARKER[7:])):
            callback = Mock()
            # A timeout fixture must remain alive; stream closure is failure.
            with self.assertRaises(SafetyError): self.attached(data, callback, caps=(0, 0))
            callback.assert_called_once_with()
        for data in (frame(MARKER[:-1]), frame(b'bad'), frame(MARKER, 2), b''):
            callback = Mock()
            with self.assertRaises(SafetyError): self.attached(data, callback, caps=(0, 0))
            callback.assert_not_called()
        for data in (frame(MARKER + b'bad'), frame(MARKER) + frame(b'bad'), frame(MARKER) * 2):
            with self.assertRaises(SafetyError): self.attached(data, Mock())

    def test_failures_always_close_attach(self):
        for error in (OSError(), TimeoutError(), KeyboardInterrupt(), SystemExit()):
            with self.subTest(error=type(error)), self.assertRaises((SafetyError, type(error))):
                self.attached(b'', error=error)
        signal = Cancellation(); signal.cancel()
        callback = Mock()
        with self.assertRaises(TimeoutError): self.attached(frame(MARKER), callback, cancellation=signal)
        callback.assert_not_called()

    def test_deadline_and_cancellation_poll_without_reading(self):
        signal = Cancellation(); signal.cancel()
        sock = Mock()
        for deadline, cancellation in ((0, None), (float('inf'), signal)):
            with self.assertRaises(TimeoutError): _Reader(sock, deadline, cancellation).readinto(bytearray(8))
        sock.recv_into.assert_not_called()

    def test_allowlist_has_no_exec_pull_or_arbitrary_requests(self):
        engine = Engine('/unused')
        with patch('forge.engine.socket.socket') as sock:
            for method, path, body in (('GET', '/version', None), ('POST', '/images/create', {}),
                                       ('POST', '/containers/' + CID + '/exec', {}),
                                       ('GET', '/info', {}), ('DELETE', '/containers/' + CID, None)):
                with self.assertRaises(SafetyError):
                    engine._request(method, path, body, deadline=float('inf'))
            sock.assert_not_called()

    def test_fixed_creation_body_and_no_pull(self):
        with patch.object(ContainerConfig, 'validate'):
            adapter = ContainerAdapter(ContainerConfig('/docker', '/socket', REF, IID))
        captured = []
        def cli(args, **kwargs):
            if args[0] == 'create':
                captured.append(args)
                raise SafetyError('offline stop')
            return 0, b'', b''
        with patch.object(adapter, '_check_image'), patch.object(adapter, '_cli', side_effect=cli):
            with self.assertRaises(SafetyError): adapter._run('probe', Limits())
        args, = captured
        name, body = Engine._creation(args)
        self.assertEqual(body['Image'], IID)
        self.assertEqual(body['HostConfig']['NetworkMode'], 'none')
        self.assertFalse(body['Tty'])
        self.assertNotIn('Binds', body['HostConfig'])
        for index, value in ((4, '--network=host'), (-5, 'print(1)'), (-9, 'fixture:latest'),
                             (-4, 'exec'), (6, '--cap-add=ALL')):
            altered = list(args); altered[index] = value
            with self.assertRaises(SafetyError): Engine._creation(altered)

    def test_json_duplicates_and_ambiguous_cleanup(self):
        engine = Engine('/unused')
        for status, data in ((200, b'{"ID":"a","ID":"b"}'), (200, b'NaN'), (404, b'{}'),
                             (200, b'invalid')):
            with patch.object(engine, '_request', return_value=(status, data)):
                with self.assertRaises(SafetyError): engine.operation(['info', '--format', '{{json .}}'])
        args = ['ps', '--all', '--filter', 'name=^/forge-fixture-' + 'a' * 32 + '$', '--format', '{{.Names}}']
        for data, expected in ((b'[]', b''), (b'[{}]', b'present')):
            with patch.object(engine, '_request', return_value=(200, data)):
                self.assertEqual(engine.operation(args)[1], expected)
        with patch.object(engine, '_request', return_value=(200, b'{}')):
            with self.assertRaises(SafetyError): engine.operation(args)

class WireTests(unittest.TestCase):
    def request(self, wire, *, method='GET', path='/info', stream=False):
        sock = Mock()
        incoming = io.BytesIO(wire)
        def recv(target):
            data = incoming.read(len(target)); target[:len(data)] = data
            return len(data)
        sock.recv_into.side_effect = recv
        endpoint = Mock(is_socket=Mock(return_value=True))
        engine = Engine('/approved/socket')
        with patch('forge.engine.checked_path', return_value=endpoint), \
                patch('forge.engine.identity', return_value=[]), patch('forge.engine.verify'), \
                patch('forge.engine.socket.socket', return_value=sock), \
                patch('forge.engine.select.select', return_value=([sock], [], [])):
            result = engine._request(method, path, deadline=float('inf'), stream=stream)
        return result, sock

    def test_http_framing_and_explicit_unix_endpoint(self):
        result, sock = self.request(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}')
        self.assertEqual(result, (200, b'{}'))
        sock.connect.assert_called_once_with('/approved/socket')
        self.assertIn(b'GET /v1.45/info HTTP/1.1', sock.sendall.call_args.args[0])
        sock.close.assert_called_once()

    def test_response_failures_close_socket(self):
        for response in (b'HTTP/1.1 500 Error\r\nContent-Length: 0\r\n\r\n',
                         b'HTTP/1.1 200 OK\r\n\r\n{}',
                         b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}',
                         b'HTTP/1.1 200 OK\r\nContent-Length: 2000000\r\n\r\n',
                         b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n',
                         b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n',
                         b'not http\r\n'):
            with self.subTest(response=response), self.assertRaises(SafetyError): self.request(response)

    def test_upgrade_preserves_frame_bytes_after_headers(self):
        raw = frame(b'abc')
        (sock, response), _ = self.request(
            b'HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\n'
            b'Connection: Upgrade\r\nUpgrade: tcp\r\n\r\n' + raw,
            method='POST', path='/containers/' + CID + '/attach?stream=1&stdout=1&stderr=1', stream=True)
        try: self.assertEqual(response.fp.read(len(raw)), raw)
        finally: response.close(); sock.close()

    def test_socket_replacement_refused_before_connect(self):
        engine = Engine('/socket')
        with patch('forge.engine.checked_path', return_value=Mock(is_socket=Mock(return_value=True))), \
                patch('forge.engine.identity', return_value=[]), \
                patch('forge.engine.verify', side_effect=SafetyError('changed')), \
                patch('forge.engine.socket.socket') as sock:
            with self.assertRaises(SafetyError): engine._request('GET', '/info', deadline=1)
            sock.assert_not_called()

    def test_bounded_chunked_metadata(self):
        result, sock = self.request(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
                                    b'2\r\n{}\r\n0\r\n\r\n')
        self.assertEqual(result, (200, b'{}'))
        sock.close.assert_called_once()
        for suffix in (b'2\r\n{', b'X\r\n', b'0\r\n'):
            with self.assertRaises(SafetyError):
                self.request(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n' + suffix)

    def test_creation_body_rejects_host_mounts_and_custom_commands(self):
        engine = Engine('/socket')
        endpoint = Mock(is_socket=Mock(return_value=True))
        for body in ({}, {'Image': IID, 'Cmd': ['sh'], 'HostConfig': {'Binds': ['/host:/host']}}):
            with patch('forge.engine.checked_path', return_value=endpoint), \
                    patch('forge.engine.identity', return_value=[]), patch('forge.engine.verify'), \
                    patch('forge.engine.socket.socket') as sock:
                with self.assertRaises(SafetyError):
                    engine._request('POST', '/containers/create?name=forge-fixture-' + 'a' * 32,
                                    body, deadline=float('inf'))
                sock.assert_not_called()
