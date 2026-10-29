"""Operator-only live synthetic conformance; never an execution permit."""
import argparse
import json
import shutil
import sys

from .container import ContainerAdapter, ContainerConfig
from .runtime import detect_capabilities

CHECKS = ('prerequisites', 'daemon_and_local_image', 'disposable_isolation')


def run(*, executable=None, socket=None, image=None, approved_images=(), live=False, expected_id=None, diagnostics=False):
    report = {'schema_version': 1, 'milestone': 'forge-0.6F',
              'status': 'UNVERIFIED', 'real_agent_execution': False,
              'execution_authorized': False,
              'capabilities': [dict(mechanism=c.mechanism, executable=c.executable,
                                    detected=c.detected, verified=False)
                               for c in detect_capabilities()],
              'checks': {name: 'UNVERIFIED' for name in CHECKS},
              'coverage': ['filesystem', 'network_disabled', 'cpu_memory_pids',
                           'timeout', 'cancellation', 'bounded_capture',
                           'bounded_artifacts', 'confirmed_cleanup'],
              'engine_candidates': {'docker': shutil.which('docker'),
                                    'orbstack': shutil.which('orb')},
              'reason': 'explicit_live_configuration_required'}
    report['guarantees'] = {name: 'UNVERIFIED' for name in report['coverage']}
    if diagnostics:
        # Local diagnostic output must not disclose discovered host paths.
        for capability in report['capabilities']:
            capability.pop('executable', None)
        report['engine_candidates'] = {name: bool(path) for name, path in
                                       report['engine_candidates'].items()}
    if not live or not all((executable, socket, image)):
        return report
    adapter = None
    stage = 'prerequisites'
    try:
        # Exact approval, no tags, defaults, registry lookup, contexts or env config.
        if image not in approved_images:
            report['checks'][stage] = 'FAIL'
            report['status'] = 'FAIL'
            report['reason'] = 'image_not_explicitly_approved'
            return report
        adapter = ContainerAdapter(ContainerConfig(executable, socket, image, expected_id))
        report['checks'][stage] = 'PASS'
        stage = 'daemon_and_local_image'
        adapter._check_daemon()
        report['checks'][stage] = 'PASS'
        stage = 'disposable_isolation'
        adapter.conform()
        if not adapter._attested or adapter._failed:
            raise RuntimeError('unconfirmed conformance')
        report['checks'][stage] = 'PASS'
        report['status'] = 'PASS'
        report['guarantees'] = {name: 'PASS' for name in report['coverage']}
        report['reason'] = 'all_fixed_live_probes_completed_and_removed'
    except (Exception, KeyboardInterrupt) as exc:
        # Never expose daemon responses, image metadata, environment or secrets.
        report['checks'][stage] = 'FAIL'
        report['status'] = 'FAIL'
        report['reason'] = stage + '_refused_or_interrupted'
        if diagnostics:
            report['diagnostic'] = (adapter.diagnostic() if stage == 'disposable_isolation'
                                    and type(adapter) is ContainerAdapter else
                                    dict(probe='unknown', stage=stage,
                                         code='interrupted' if isinstance(exc, KeyboardInterrupt)
                                         else 'refused'))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--live', action='store_true')
    parser.add_argument('--diagnostics', action='store_true',
                        help='opt in to fixed, redacted local failure codes')
    parser.add_argument('--docker')
    parser.add_argument('--socket')
    parser.add_argument('--image')
    parser.add_argument('--approve-image', action='append', default=[])
    args = parser.parse_args(argv)
    report = run(executable=args.docker, socket=args.socket, image=args.image,
                 approved_images=args.approve_image, live=args.live, diagnostics=args.diagnostics)
    print(json.dumps(report, sort_keys=True))
    return {'PASS': 0, 'FAIL': 1, 'UNVERIFIED': 2}[report['status']]


if __name__ == '__main__':
    sys.exit(main())
