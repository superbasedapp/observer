# syntax=docker/dockerfile:1.7
#
# Observer's default sandbox image (sandbox plan v2 section 12.3, ledger
# SBX-IMG-1). It carries no agent CLI: the host's own toolchain is bound in
# read-only at launch (tool delivery, plan section 5.4), so this is only the
# userland that toolchain runs on. Build it with build.sh, which pins every
# input and makes the build reproducible; do not build it by hand for a
# release.
#
# Inputs, all pinned:
#   BASE             the base image by digest (read from Docker Hub on
#                    2026-10-22: debian:bookworm-slim's index digest)
#   DEBIAN_SNAPSHOT  the snapshot.debian.org timestamp the packages come from
#   SOURCE_DATE_EPOCH  set by build.sh from the recipe's last commit
ARG BASE=debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8

FROM ${BASE} AS image
ARG DEBIAN_SNAPSHOT
ARG SOURCE_DATE_EPOCH
COPY packages.txt /tmp/observer-packages.txt
RUN set -eu; \
    test -n "${DEBIAN_SNAPSHOT}"; \
    rm -f /etc/apt/sources.list.d/*; \
    printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s bookworm main\ndeb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/%s bookworm-security main\n' \
        "${DEBIAN_SNAPSHOT}" "${DEBIAN_SNAPSHOT}" > /etc/apt/sources.list; \
    apt-get -o Acquire::Check-Valid-Until=false update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        $(grep -v '^#' /tmp/observer-packages.txt | grep -v '^$'); \
    mkdir -p /usr/share/observer-sandbox; \
    dpkg-query -W -f '${Package}\t${Version}\t${Architecture}\n' | LC_ALL=C sort > /usr/share/observer-sandbox/packages.tsv; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* /var/cache/debconf/*-old /var/log/* /tmp/observer-packages.txt \
        /var/cache/ldconfig/aux-cache /usr/share/doc /usr/share/man /usr/share/info; \
    find / -xdev -name '__pycache__' -type d -prune -exec rm -rf {} +
LABEL org.opencontainers.image.title="observer-sandbox" \
      org.opencontainers.image.description="Observer's default sandbox userland; no agent CLI" \
      org.opencontainers.image.licenses="Apache-2.0" \
      app.superbased.observer.sandbox.agent-cli="none"
WORKDIR /

# The package list alone, for the SBOM (build.sh exports this stage).
FROM scratch AS packages
COPY --from=image /usr/share/observer-sandbox/packages.tsv /packages.tsv
