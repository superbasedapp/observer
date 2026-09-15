// Package machineid computes a best-effort, org-salted machine fingerprint
// used by Enterprise-Managed Tenancy to bind one managed node to one machine
// (Arc 4 P6a, docs/plans/org-admin-comprehensive-control-plane-2026-08-19.md
// §9).
//
// It is deliberately EVIDENCE, not PREVENTION. The fingerprint is derived from
// the most stable OS source available on the running host, but that host is
// controlled by the very developer the managed plane observes: the raw source
// can be edited (e.g. /etc/machine-id), a fresh VM or container can be spun up,
// or the binary patched. Under WSL2 the Linux source identifies the DISTRO, not
// the Windows host, so a second distro reads as a second machine. Cloned images
// and bare containers may share or lack a stable source entirely. The product
// therefore treats a machine identity as a dedup anchor and a tamper-evidence
// signal (a changed or colliding identity is surfaced to the org admin), while
// true prevention comes from OS/device ownership + managed-settings/MDM, per the
// §5 legal/ownership gate and the native-console template.
//
// The identity is salted with the org id and one-way hashed, so the same
// machine enrolling in two different orgs yields two unrelated identities (no
// cross-org machine correlation) and the org never learns the raw OS id.
//
// # Source ladder
//
// rawIdentity walks these rungs in order and takes the first that yields a
// value. Each rung is strictly more stable than the one below it, so a host
// never silently downgrades to a weaker source while a stronger one exists:
//
//  1. The OS-NATIVE id: /etc/machine-id (then /var/lib/dbus/machine-id) on
//     Linux, IOPlatformUUID on darwin, MachineGuid on windows. Survives
//     reboots, renames and reinstalls-in-place; the source of record for every
//     ordinary workstation.
//
//  2. The PERSISTED SEED at <home>/.observer/machine-id — 16 random bytes
//     minted once, hex-encoded, written 0600 with O_EXCL (so two racing
//     processes cannot mint two identities), and read verbatim thereafter.
//     Added because containers carry no OS-native id: without this rung the
//     hostname below becomes the identity, and an orchestrator that remints
//     the hostname on every restart (Azure Container Instances issues a fresh
//     SandboxHost-<n>) orphans the machine binding each time the container
//     cycles, stranding the node until a human re-enrols it. The seed lives in
//     the observer data dir, so any deployment that already mounts a volume
//     for observer.db persists its identity by the same act. A host that
//     reaches rung 1 never touches this file, so shipping the rung changes no
//     existing machine's identity.
//
//  3. The HOSTNAME. Weakest source — hostnames collide across a fleet and
//     change under the operator's feet — but the only one left when the
//     filesystem is read-only and rung 2 cannot mint. Kept last rather than
//     dropped: an unstable identity still beats none for dedup.
//
// Nothing readable at any rung yields the empty identity, which ForOrg reports
// as the first-class "unbindable" value rather than an error.
//
// Module boundary (CLAUDE.md #1): the pure core — source ordering, salting, and
// hashing — carries no I/O. The OS reads (files, hostname, platform tools) live
// behind package-level func vars with OS defaults, overridable in tests.
package machineid
