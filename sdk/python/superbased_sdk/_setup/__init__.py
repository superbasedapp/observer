"""``superbased-sdk setup``: one command from an app to its first trace
(plan docs/plans/sdk-quickstart-one-command-plan-2026-11-25.md, 3.5 to 3.8).

Run it as ``uvx superbased-sdk setup``, ``pipx run superbased-sdk setup`` or
``python -m superbased_sdk setup``. Standard library only (beside the SDK
itself, which the hello span goes through), and the runtime SDK never
imports this package.

Modules: ``plan`` (the pure decision tables), ``detect`` (the project),
``cloud`` (the online device sign-in), ``local`` (this computer's enable),
``store`` (the SDK-held key file's one writer), ``hello`` (the hello span
and its arrival), ``out`` (output and the secret guard), ``cli`` (the
command).
"""

from __future__ import annotations

from .cli import main, run

__all__ = ["main", "run"]
