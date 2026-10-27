"""Local worktree management; this package does not execute jobs."""
from .manager import Manager
from .safety import SafetyError

__all__ = ["Manager", "SafetyError"]
