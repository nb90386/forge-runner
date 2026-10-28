"""Offline runner contracts. Mocked success never attests a real daemon."""
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from forge.conformance import main, run

IMAGE = 'audited@sha256:' + '1' * 64


class ConformanceTests(unittest.TestCase):
    def configured(self, **kwargs):
        return run(executable='/docker', socket='/socket', image=IMAGE,
                   approved_images=[IMAGE], live=True, **kwargs)

    def test_missing_opt_in_never_contacts_engine(self):
        with patch('forge.conformance.ContainerAdapter') as adapter:
            report = run()
        adapter.assert_not_called()
        self.assertEqual(report['status'], 'UNVERIFIED')
        self.assertEqual(set(report['checks'].values()), {'UNVERIFIED'})

    def test_approval_is_exact_and_required(self):
        with patch('forge.conformance.ContainerAdapter') as adapter:
            report = run(executable='/docker', socket='/socket', image=IMAGE,
                         approved_images=['audited:latest'], live=True)
        adapter.assert_not_called()
        self.assertEqual(report['status'], 'FAIL')

    def test_failure_keeps_unrun_checks_unverified_and_redacts(self):
        with patch('forge.conformance.ContainerAdapter', side_effect=ValueError('SECRET')):
            report = self.configured()
        self.assertEqual(report['checks']['prerequisites'], 'FAIL')
        self.assertEqual(report['checks']['disposable_isolation'], 'UNVERIFIED')
        self.assertNotIn('SECRET', json.dumps(report))

    def test_noop_or_skipped_conformance_cannot_pass(self):
        for failure in (False, True):
            with patch('forge.conformance.ContainerAdapter') as cls:
                cls.return_value._attested = False
                cls.return_value._failed = failure
                report = self.configured()
            self.assertEqual(report['status'], 'FAIL')

    def test_cleanup_failure_cannot_pass(self):
        with patch('forge.conformance.ContainerAdapter') as cls:
            cls.return_value._attested = True
            cls.return_value._failed = True
            report = self.configured()
        self.assertEqual(report['status'], 'FAIL')

    def test_completed_fixed_probes(self):
        with patch('forge.conformance.ContainerAdapter') as cls:
            cls.return_value._attested = True
            cls.return_value._failed = False
            report = self.configured()
            cls.return_value.conform.assert_called_once_with()
        self.assertEqual(report['status'], 'PASS')
        self.assertFalse(report['execution_authorized'])

    def test_cli_unverified_is_nonzero_structured_json(self):
        with patch('sys.stdout', new_callable=io.StringIO) as output:
            code = main([])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())['status'], 'UNVERIFIED')
