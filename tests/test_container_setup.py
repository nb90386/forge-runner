"""Offline operator setup refusals; no Docker invocation."""
import copy
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import Mock, patch

from test_container import ContainerConfig, SafetyError

SCRIPT = Path(__file__).resolve().parents[1] / 'tools/container-fixture/setup.py'
spec = importlib.util.spec_from_file_location('container_setup', SCRIPT)
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)
# Explicitly synthetic test values, never trusted or sent to Docker.
REF = 'example.invalid/test@sha256:' + 'a' * 64
IID = 'sha256:' + 'b' * 64


def image():
    return dict(Id=IID, RepoDigests=[REF], Os='linux', Architecture='arm64',
                Config=dict(Env=setup.PATH_ENV, User='65534:65534',
                            WorkingDir='/workspace', Cmd=None, Entrypoint=None))


class SetupTests(unittest.TestCase):
    def test_hub_familiar_and_canonical_digest_metadata(self):
        suffix = '@sha256:' + 'a' * 64
        names = ('python', 'library/python', 'docker.io/python',
                 'docker.io/library/python', 'index.docker.io/library/python')
        for supplied in names:
            for stored in names:
                with self.subTest(supplied=supplied, stored=stored):
                    obj = image(); obj['RepoDigests'] = [stored + suffix]
                    engine = Mock(); engine._json.return_value = [obj]
                    self.assertEqual(setup.inspect_image(engine, supplied + suffix, IID)['Id'], IID)
                    # The runtime must enforce the same digest interpretation.
                    runtime = object.__new__(setup.ContainerAdapter)
                    runtime.config = ContainerConfig('/docker', '/socket', supplied + suffix, IID)
                    runtime._image_id = IID
                    runtime._json = engine._json
                    runtime._check_image()
                    engine._json.assert_called_with(['image', 'inspect', supplied + suffix])

    def test_digest_evidence_mismatches_fail_closed_before_build(self):
        suffix = '@sha256:' + 'a' * 64
        reference = 'python' + suffix
        for evidence in (None, [], {}, 'python' + suffix,
                         [IID], ['python:latest'],
                         ['docker.io/library/python@sha256:' + 'c' * 64],
                         ['evil.invalid/library/python' + suffix],
                         ['registry-1.docker.io/library/python' + suffix],
                         ['docker.io/attacker/python' + suffix],
                         ['docker.io/library/python-evil' + suffix],
                         ['docker.io/library/python@sha512:' + 'a' * 64],
                         ['docker.io/library/python@sha256:' + 'a' * 63],
                         [None, {}, 'python:latest']):
            with self.subTest(evidence=evidence):
                obj = image(); obj['RepoDigests'] = evidence
                # A matching ID/tag/descriptor cannot replace RepoDigests.
                obj['RepoTags'] = ['python:latest']
                obj['Descriptor'] = {'digest': 'sha256:' + 'a' * 64}
                runtime = object.__new__(setup.ContainerAdapter)
                runtime.config = ContainerConfig('/docker', '/socket', reference, IID)
                runtime._image_id = IID
                runtime._json = Mock(return_value=[obj])
                with self.assertRaises(SafetyError):
                    runtime._check_image()
                with patch.object(setup, 'ContainerAdapter') as adapter:
                    adapter.return_value._json.return_value = [obj]
                    error = io.StringIO()
                    with contextlib.redirect_stderr(error):
                        self.assertEqual(setup.main(['build', '--docker', '/docker',
                            '--socket', '/socket', '--base', reference, '--trust-base']), 1)
                    self.assertIn('BLOCKED', error.getvalue())
                    adapter.return_value._cli.assert_not_called()

    def test_build_sends_only_reviewed_context_and_records_id(self):
        commands = []
        def cli(args, **kwargs):
            commands.append(args)
            context = Path(args[-1])
            self.assertEqual([p.name for p in context.iterdir()], ['Dockerfile'])
            self.assertEqual((context / 'Dockerfile').read_bytes(),
                             SCRIPT.with_name('Dockerfile').read_bytes())
            self.assertIn('BASE=' + REF, args)
            self.assertIn('--pull=false', args)
            self.assertIn('--network=none', args)
            self.assertIn('--platform=linux/arm64', args)
            iid_file = Path(args[args.index('--iidfile') + 1])
            self.assertNotEqual(iid_file.parent, context)
            self.assertEqual(iid_file.parent.stat().st_mode & 0o777, 0o700)
            self.assertFalse(iid_file.exists())
            iid_file.write_text(IID + '\n')
            return 0, b'', b''
        with patch.object(setup, 'ContainerAdapter') as adapter:
            engine = adapter.return_value
            engine._json.return_value = [image()]
            engine._cli.side_effect = cli
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(setup.main(['build', '--docker', '/docker', '--socket', '/socket',
                    '--base', REF, '--trust-base']), 0)
            self.assertEqual(len(commands), 1)
            self.assertIn(IID, output.getvalue())
            self.assertIn('UNVERIFIED', output.getvalue())
            self.assertFalse(Path(commands[0][-1]).exists())
            self.assertFalse(Path(commands[0][commands[0].index('--iidfile') + 1]).parent.exists())
            self.assertEqual(engine._json.call_args_list[-1].args[0],
                             ['image', 'inspect', IID])

    def test_changed_tag_cannot_substitute_another_image(self):
        replacement = image()
        replacement['Id'] = 'sha256:' + 'c' * 64
        tag = 'forge-conformance:arm64'
        tagged_image = image()
        def cli(args, **kwargs):
            nonlocal tagged_image
            Path(args[args.index('--iidfile') + 1]).write_text(IID)
            tagged_image = replacement
            return 0, b'', b''
        def inspect(args):
            return [tagged_image if args[-1] == tag else image()]
        with patch.object(setup, 'ContainerAdapter') as adapter:
            engine = adapter.return_value
            engine._cli.side_effect = cli
            engine._json.side_effect = inspect
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(setup.main(['build', '--docker', '/docker', '--socket', '/socket',
                    '--base', REF, '--trust-base', '--tag', tag]), 0)
            self.assertEqual(json.loads(output.getvalue())['built_id'], IID)
            self.assertEqual([call.args[0] for call in engine._json.call_args_list],
                             [['image', 'inspect', REF], ['image', 'inspect', IID]])

    def test_build_rejects_missing_malformed_mismatched_ids_and_cleans_up(self):
        for contents in (None, '', 'sha256:' + 'g' * 64, 'sha256:' + 'b' * 63,
                         IID + '\n' + IID, IID):
            with self.subTest(contents=contents), patch.object(setup, 'ContainerAdapter') as adapter:
                paths = []
                def cli(args, **kwargs):
                    iid_file = Path(args[args.index('--iidfile') + 1])
                    paths.extend([iid_file.parent, Path(args[-1])])
                    if contents is not None:
                        iid_file.write_text(contents)
                    return 0, b'', b''
                engine = adapter.return_value
                other = image(); other['Id'] = 'sha256:' + 'c' * 64
                engine._json.side_effect = [[image()], [other]]
                engine._cli.side_effect = cli
                output = io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(setup.main(['build', '--docker', '/docker', '--socket', '/socket',
                        '--base', REF, '--trust-base']), 1)
                self.assertEqual(output.getvalue(), '')
                self.assertTrue(paths)
                self.assertTrue(all(not path.exists() for path in paths))
                self.assertEqual(engine._json.call_count, 2 if contents == IID else 1)

    def test_exact_identity_and_config(self):
        engine = Mock()
        engine._json.return_value = [image()]
        self.assertEqual(setup.inspect_image(engine, REF, IID, True)['Id'], IID)
        for field, value in [('RepoDigests', []), ('Id', 'sha256:' + 'c' * 64),
                             ('Os', 'darwin'), ('Architecture', 'amd64')]:
            obj = image(); obj[field] = value
            engine._json.return_value = [obj]
            with self.subTest(field=field), self.assertRaises(SafetyError):
                setup.inspect_image(engine, REF, IID, True)
        for field, value in [('Env', setup.PATH_ENV + ['PYTHON_VERSION=3.13']),
                             ('Volumes', {'/secret': {}}), ('Cmd', ['sh']),
                             ('Entrypoint', ['sh']), ('User', 'root'),
                             ('WorkingDir', '/root'), ('OnBuild', ['RUN bad']),
                             ('Healthcheck', {'Test': ['CMD', 'bad']})]:
            obj = copy.deepcopy(image()); obj['Config'][field] = value
            engine._json.return_value = [obj]
            with self.subTest(field=field), self.assertRaises(SafetyError):
                setup.inspect_image(engine, REF, IID, True)

    def test_missing_trust_digest_or_id_never_contacts_engine(self):
        for action, extra in [('build', []), ('build', ['--base', REF]),
                              ('audit', ['--image', REF]),
                              ('live', ['--image', 'python:latest', '--expected-id', IID])]:
            with patch.object(setup, 'ContainerAdapter') as adapter, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(setup.main([action, '--docker', '/docker',
                                            '--socket', '/socket', *extra]), 1)
                adapter.assert_not_called()

    def test_live_passes_audited_id_into_conformance(self):
        with patch.object(setup, 'ContainerAdapter') as adapter, patch.object(setup, 'run') as live:
            adapter.return_value._json.return_value = [image()]
            live.return_value = {'status': 'PASS'}
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(setup.main(['live', '--docker', '/docker', '--socket', '/socket',
                    '--image', REF, '--expected-id', IID]), 0)
            self.assertEqual(live.call_args.kwargs['expected_id'], IID)
            self.assertEqual(adapter.call_args.args[0].expected_id, IID)

    def test_metadata_failure_never_runs_live_probes(self):
        with patch.object(setup, 'ContainerAdapter') as adapter, patch.object(setup, 'run') as live:
            adapter.return_value._json.return_value = [image()]
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(setup.main(['live', '--docker', '/docker', '--socket', '/socket',
                    '--image', REF, '--expected-id', 'sha256:' + 'c' * 64]), 1)
            live.assert_not_called()

    def test_actual_paths_not_symlink_or_regular_file_socket(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            binary = root / 'docker'; binary.write_text('#!/bin/sh\nexit 1\n'); binary.chmod(0o700)
            endpoint = root / 'engine.sock'
            with self.assertRaises(SafetyError):
                ContainerConfig(str(binary), str(binary), REF).validate()
            link = root / 'link'; link.symlink_to(binary)
            with self.assertRaises(SafetyError):
                ContainerConfig(str(link), str(binary), REF).validate()
            with socket.socket(socket.AF_UNIX) as listener:
                try: listener.bind(str(endpoint))
                except PermissionError: self.skipTest('sandbox denies Unix socket binding')
                ContainerConfig(str(binary), str(endpoint), REF).validate()
                with self.assertRaises(SafetyError):
                    ContainerConfig(str(link), str(endpoint), REF).validate()
                with self.assertRaises(SafetyError):
                    ContainerConfig(str(binary), str(binary), REF).validate()
                binary.chmod(0o777)
                with self.assertRaises(SafetyError):
                    ContainerConfig(str(binary), str(endpoint), REF).validate()


if __name__ == '__main__':
    unittest.main()
