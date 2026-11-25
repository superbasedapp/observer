"""``python -m superbased_sdk setup [flags]``: the setup command (plan 3.5).
Only the ``setup`` command exists; it lives in ``superbased_sdk._setup``,
which the runtime SDK never imports."""

import sys

from ._setup import main

sys.exit(main())
