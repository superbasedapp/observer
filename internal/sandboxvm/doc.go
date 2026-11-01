// Package sandboxvm is the pure core of the Cloud Hypervisor microVM
// sandbox driver (sandbox plan v2 sections 4.2 to 4.8, 5.4, 5.5, 6 and 13
// P4; lane SBX-P4; the cloud-hypervisor registry row, beta).
//
// It holds every decision the driver makes and none of its I/O:
//
//   - probe.go: the probe ladder over injected local facts (platform, the
//     active switch, /dev/kvm, nested virtualisation, the two programs and
//     their version, the verified guest image set); nothing below the
//     active row runs unless the driver is active and listed, and the
//     probe never boots a VM and never fetches;
//   - config.go: the vm.create body and the VMM's argv from a run plan
//     (kernel, initramfs, the fixed-table kernel command line carrying the
//     signed verity root hash, a read-only raw rootfs, one vsock device,
//     the planned shares, shared memory, a serial file, no network device,
//     the event monitor on an inherited descriptor);
//   - readback.go: the strict judge of what vm.info reports against that
//     plan (any NIC, another CID, an unplanned share or disk, a writable
//     rootfs or unshared memory is built_below_plan);
//   - handshake.go: the hybrid vsock CONNECT exchange (a fuzz target);
//   - disk.go and mapping.go: the workspace delivery table (virtiofs or a
//     disk_image copy) and the disk plans;
//   - sweep.go: the orphan sweep's decisions over recorded processes.
//
// The REST client is internal/sandboxvmm; the processes, sockets and files
// are the cmd layer's (cmd/observer/terminal_sandbox_vm*.go). The package
// is pinned free of database/sql, net/http, os/exec and fsnotify
// (imports_test.go).
package sandboxvm
