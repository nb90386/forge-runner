#!/usr/bin/env python3
"""Explicit operator actions only. No pulls, registry login, push or agent launch."""
import argparse
import json
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from forge.container import ContainerAdapter, ContainerConfig, has_repository_digest
from forge.conformance import run
from forge.safety import SafetyError

PATH_ENV = ['PATH=/usr/local/bin:/usr/bin:/bin']
DIGEST = r'[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}'


def pinned(value):
    if not re.fullmatch(DIGEST, value):
        raise SafetyError('supply an independently verified repository@sha256 digest')
    return value


def inspect_image(adapter, reference, expected_id=None, fixture=False):
    obj, = adapter._json(['image', 'inspect', reference])
    cfg = obj['Config']
    if not has_repository_digest(obj, reference):
        raise SafetyError('BLOCKED: trusted local repository digest evidence unavailable; '
                          'use independently verified provisioning (see fixture README)')
    if (obj.get('Os') != 'linux'
            or obj.get('Architecture') != 'arm64'
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', obj.get('Id', ''))):
        raise SafetyError('exact local Linux ARM64 repository digest required')
    if expected_id is not None and obj['Id'] != expected_id:
        raise SafetyError('local image ID differs from audited build ID')
    if cfg.get('OnBuild'):
        raise SafetyError('base build triggers refused')
    if fixture and (cfg.get('Env') != PATH_ENV or cfg.get('Volumes')
                    or cfg.get('Entrypoint') or cfg.get('Cmd')
                    or cfg.get('User') != '65534:65534'
                    or cfg.get('WorkingDir') != '/workspace'
                    or cfg.get('OnBuild') or cfg.get('Healthcheck')):
        raise SafetyError('unexpected fixture image configuration')
    return obj


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('build', 'audit', 'live'))
    p.add_argument('--diagnostics', action='store_true',
                   help='live only: fixed, redacted local failure codes')
    p.add_argument('--docker', required=True)
    p.add_argument('--socket', required=True)
    p.add_argument('--base', help='independently trusted, already local base digest')
    p.add_argument('--trust-base', action='store_true', help='operator verified base provenance')
    p.add_argument('--tag', default='forge-conformance:arm64')
    p.add_argument('--image', help='independently provisioned fixture repository digest')
    p.add_argument('--expected-id', help='sha256 image ID printed by build')
    args = p.parse_args(argv)
    if args.diagnostics and args.action != 'live':
        p.error('--diagnostics requires live')
    try:
        reference = args.base if args.action == 'build' else args.image
        pinned(reference or '')
        if args.action == 'build' and not args.trust_base:
            raise SafetyError('STOP: no independently trusted base approved')
        if args.action in ('audit', 'live') and not re.fullmatch(
                r'sha256:[0-9a-f]{64}', args.expected_id or ''):
            raise SafetyError('expected build image ID required')
        config = ContainerConfig(args.docker, args.socket, reference, args.expected_id)
        adapter = ContainerAdapter(config)
        if args.action == 'build':
            inspect_image(adapter, args.base)
            if not re.fullmatch(r'[a-z0-9][a-z0-9/_.-]*:[a-z0-9_.-]+', args.tag):
                raise SafetyError('explicit local build tag required')
            # Only this reviewed Dockerfile enters the build context.
            with tempfile.TemporaryDirectory(prefix='forge-build-') as directory, \
                    tempfile.TemporaryDirectory(prefix='forge-iid-') as iid_directory:
                iid_file = Path(iid_directory, 'image.id')
                Path(directory, 'Dockerfile').write_bytes(
                    Path(__file__).with_name('Dockerfile').read_bytes())
                rc, _, _ = adapter._cli(['build', '--pull=false', '--network=none',
                    '--platform=linux/arm64', '--build-arg', 'BASE=' + args.base,
                    '--build-arg', 'SOURCE_DATE_EPOCH=0',
                    '--iidfile', str(iid_file), '--tag', args.tag, directory], timeout=300)
                if rc:
                    raise SafetyError('build refused; inspect builder availability locally')
                built_id = iid_file.read_text().strip()
                if not re.fullmatch(r'sha256:[0-9a-f]{64}', built_id):
                    raise SafetyError('valid build image ID required')
                obj, = adapter._json(['image', 'inspect', built_id])
                if obj['Id'] != built_id:
                    raise SafetyError('local image ID differs from build image ID')
            print(json.dumps({'built_id': obj['Id'], 'base': args.base,
                              'status': 'UNVERIFIED',
                              'next': 'provision repository digest; audit with this exact ID'}))
            return 0
        obj = inspect_image(adapter, args.image, args.expected_id, fixture=True)
        adapter._check_daemon()
        if args.action == 'audit':
            print(json.dumps({'image': args.image, 'id': obj['Id'],
                              'status': 'UNVERIFIED', 'reason': 'metadata_only'}))
            return 0
        report = run(executable=args.docker, socket=args.socket, image=args.image,
                     approved_images=(args.image,), live=True, expected_id=args.expected_id,
                     diagnostics=args.diagnostics)
        print(json.dumps(report, sort_keys=True))
        return 0 if report['status'] == 'PASS' else 1
    except SafetyError as exc:
        # SafetyError messages in these boundaries are fixed runner-owned text.
        print('STOP: ' + str(exc), file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TimeoutError):
        print('STOP: prerequisites, identity, configuration or isolation refused; '
              'see tools/container-fixture/README.md for diagnostics', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
