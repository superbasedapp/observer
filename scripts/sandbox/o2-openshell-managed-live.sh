#!/usr/bin/env bash
# o2-openshell-managed-live.sh: lane O2's live check of the managed local
# gateway (live register row O2-L1): Observer starts, uses, survives a
# daemon restart with, and stops its own private OpenShell gateway.
#
# It is o1b-openshell-live.sh in its --managed mode (one script, so the
# two rows share the box checks, the strict judging, not_run distinct from
# fail, and one receipt on every exit). Run it unattended on a FRESH native
# Linux host (Ubuntu 24.04, kernel 6.2+) with only what the OpenShell
# v0.1.6 package installs (the openshell CLI and openshell-gateway), Docker
# Engine with this user in the docker group, and a systemd user manager (an
# SSH login, or lingering). The package installer also enables and starts
# the user's own openshell-gateway.service on the same Docker engine: leave
# it running, as a default install has it. Observer never uses or stops it,
# and the run judges that the two gateways share the engine without one
# stopping the other's boxes (managed_coexists_with_package_gateway,
# finding F-027; not_run when it is not running). Nothing is pulled by
# hand: the private gateway
# pulls its own supervisor and sandbox images at its first start. Observer
# is built static (CGO_ENABLED=0) unless --observer names a binary.
#
# Usage:
#   scripts/sandbox/o2-openshell-managed-live.sh [--observer PATH] [--out DIR]
#
# Exit 0 when every judged check passed, 1 when one failed or did not run,
# 2 on a precondition the host does not meet (the receipt says which).
set -euo pipefail
exec "$(dirname "$0")/o1b-openshell-live.sh" --managed "$@"
