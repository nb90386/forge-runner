"""Fail-closed synthetic runtime. Inventory is not isolation attestation.

No agent execution, credential loading, preparation manifests or lease APIs.
"""
from dataclasses import asdict, dataclass, field
from pathlib import Path
import math
import shutil
import tempfile
from threading import Event
from typing import Protocol

from .safety import SafetyError, checked_path, identity, verify


# These are runner-owned test identifiers, never executable names or shell text.
SYNTHETIC_OPERATIONS = frozenset({'noop', 'capture-fixture', 'artifact-fixture',
                                  'timeout-fixture', 'cancel-fixture', 'resource-fixture'})
GUARANTEES = ('workspace_boundary', 'home_hidden', 'credentials_hidden',
              'network_disabled', 'cpu_limit', 'memory_limit', 'process_limit',
              'wall_time_limit', 'bounded_capture', 'terminate_then_kill')


@dataclass(frozen=True)
class Capability:
    mechanism: str
    executable: str = ''
    detected: bool = False
    verified: bool = False
    supported: bool = False
    reason: str = 'No verified adapter; execution prohibited'


def detect_capabilities():
    """Passive executable discovery only; no daemon access, pulls or installation.

    Presence does not prove daemon availability, cgroups, network policy, VM mount
    semantics, or whole-container termination. Never select a backend from this.
    """
    result = []
    for name in ('docker', 'podman', 'nerdctl', 'sandbox-exec', 'bwrap'):
        executable = shutil.which(name) or ''
        result.append(Capability(name, executable, bool(executable)))
    return tuple(result)


@dataclass(frozen=True)
class Limits:
    cpu: float = 1.0
    memory_bytes: int = 268435456
    processes: int = 32
    wall_seconds: float = 30.0
    grace_seconds: float = 2.0
    stdout_bytes: int = 65536
    stderr_bytes: int = 65536
    artifact_bytes: int = 1048576
    artifact_count: int = 8

    def validate(self):
        for name, maximum in (('cpu', 8), ('wall_seconds', 300), ('grace_seconds', 10)):
            value = getattr(self, name)
            if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= maximum:
                raise SafetyError('invalid runtime limit: ' + name)
        for name, maximum in (('memory_bytes', 2147483648), ('processes', 256),
                              ('stdout_bytes', 1048576), ('stderr_bytes', 1048576),
                              ('artifact_bytes', 16777216), ('artifact_count', 64)):
            value = getattr(self, name)
            if type(value) is not int or not 0 < value <= maximum:
                raise SafetyError('invalid runtime limit: ' + name)
        if self.grace_seconds > self.wall_seconds:
            raise SafetyError('termination grace exceeds wall deadline')


@dataclass(frozen=True)
class SyntheticRequest:
    workspace: str
    operation: str = 'noop'
    limits: Limits = field(default_factory=Limits)
    network: bool = False
    workspace_access: str = 'rw'


class Cancellation:
    """Trusted supervisor signal; no job-controlled callback or command."""
    def __init__(self):
        self._event = Event()

    def cancel(self):
        self._event.set()

    @property
    def requested(self):
        return self._event.is_set()


@dataclass(frozen=True)
class ExecutionResult:
    status: str
    reason: str
    audit: dict
    started: bool = False
    exit_code: object = None
    stdout: bytes = b''
    stderr: bytes = b''
    artifacts: tuple = ()

    def manifest(self):
        # Output is empty in this milestone; keep binary capture out of JSON.
        return {**self.audit, 'status': self.status, 'reason': self.reason,
                'started': self.started, 'exit_code': self.exit_code,
                'stdout_bytes': len(self.stdout), 'stderr_bytes': len(self.stderr),
                'artifact_count': len(self.artifacts)}


class IsolatedRuntime(Protocol):
    def execute(self, request: SyntheticRequest, cancellation=None) -> ExecutionResult:
        """Never launch without verified isolation. Future backend obligations:

        Enforce all requested bounds before launch; use a monotonic deadline.
        On cancel/deadline/lease loss, stop the entire isolated process tree,
        then force kill after bounded grace and confirm removal. Capture streams
        incrementally with byte caps and artifacts with no-follow regular-file
        reads, count/total-byte caps. Never return success on cleanup uncertainty.
        """
        ...


class Runtime:
    """Trusted local configuration, separate from dispatch and untrusted content.

    Explicit paths are exact, identity-pinned, in-memory operator configuration,
    not authorization to execute agents. Only the typed container adapter is accepted.
    """
    def __init__(self, approved_worktrees=(), *, container=None):
        from .container import ContainerAdapter
        if container is not None and type(container) is not ContainerAdapter:
            raise SafetyError("typed container adapter required")
        self._container = container
        self._approved = {}
        for value in approved_worktrees:
            path = checked_path(value)
            if not path.is_dir() or path == Path('/') or path == Path.home():
                raise SafetyError('explicit workspace directory required')
            self._approved[str(path)] = identity(path)

    def execute(self, request, cancellation=None):
        audit = {'schema_version': 1, 'adapter': 'forge-0.6B',
                 'real_agent_execution': False, 'execution_authorized': False,
                 'backend': None, 'enforced_guarantees': [],
                 'unverified_guarantees': list(GUARANTEES)}
        def outcome(status, reason):
            return ExecutionResult(status, reason, audit)
        if type(request) is not SyntheticRequest:
            return outcome('rejected', 'synthetic_request_required')
        try:
            if request.operation not in SYNTHETIC_OPERATIONS:
                return outcome('rejected', 'operation_not_allowlisted')
            if request.network is not False or request.workspace_access not in ('ro', 'rw'):
                return outcome('rejected', 'unsupported_isolation_configuration')
            if type(request.limits) is not Limits:
                return outcome('rejected', 'invalid_limits')
            request.limits.validate()
            path = checked_path(request.workspace)
            anchor = self._approved.get(str(path))
            if anchor is None:
                return outcome('rejected', 'workspace_not_explicitly_approved')
            verify(path, anchor)
            if not path.is_dir():
                return outcome('rejected', 'workspace_not_directory')
        except (SafetyError, OSError, TypeError, ValueError):
            return outcome('rejected', 'invalid_workspace_or_limits')
        audit.update(operation=request.operation, limits=asdict(request.limits),
                     network=False, workspace_access=request.workspace_access)
        if cancellation is not None and type(cancellation) is not Cancellation:
            return outcome('rejected', 'invalid_cancellation')
        if cancellation is not None and cancellation.requested:
            return outcome('canceled', 'canceled_before_start')
        audit['capabilities'] = [asdict(item) for item in detect_capabilities()]
        if self._container is None:
            return outcome('unsupported', 'no_verified_isolation_backend')
        # Synthetic workspaces are empty disposable admission tokens. No host
        # directory is mounted, copied, or executed, including approved content.
        if Path(tempfile.gettempdir()).resolve() not in path.parents or any(path.iterdir()):
            return outcome('rejected', 'empty_disposable_workspace_required')
        try:
            status, code, stdout, stderr, artifacts = self._container.execute(request, cancellation)
        except Exception:
            return ExecutionResult('unsupported', 'container_isolation_or_cleanup_unverified',
                                   audit, started=self._container._attested)
        audit.update(adapter='forge-0.6C', backend='docker-compatible',
                     enforced_guarantees=list(GUARANTEES), unverified_guarantees=[])
        return ExecutionResult(status if code in (None, 0) else 'failed',
                               'synthetic_container_result', audit, True, code,
                               stdout, stderr, artifacts)
