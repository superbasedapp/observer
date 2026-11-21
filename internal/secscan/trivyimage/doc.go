// Package trivyimage is the pure core of the Trivy image driver, component
// security.scan.image.trivy (OS and CI vulnerability scanning plan section
// 6.7, operator ruling Q6, lane OS-2 T): the switchable alternative to the
// native route A (security.scan.os) for a container image's OS packages.
//
// It holds, as data and pure functions:
//
//   - the flag table of one run (`trivy image --input <tar>` or `trivy
//     rootfs <dir>`, vulnerability scanner and OS packages only, every
//     network path a flag can turn off turned off, Observer's own cache
//     directory and never a registry, a daemon, a server or a token) and the
//     --help check of the pinned flags;
//   - the reading of Trivy's JSON report (schema 2) under a size cap;
//   - the mapping of its os-pkgs results onto dependency findings in route
//     A's shape (category vulnerable_dependency, the CVE as the rule id,
//     `<release> <package>@<version>` as the evidence), with Trivy's own
//     severity, a fix hint naming the fixed version, a "no fix available
//     yet" note, and kernel packages left out by depscan's kernel rule;
//   - the canary root filesystem (Debian 12 libc6 at 2.36-9+deb12u2, flagged
//     by DSA-5514-1 / CVE-2023-4911) scanned in the same run first: a run
//     whose canary is not flagged is "not scanned: self_test_failed";
//   - the run seam (Driver.Scan): the version probe, the help check, the
//     canary and the scan through the shared runner (internal/extrun), under
//     its caps and only isolated (Trivy's engine row requires isolation, as
//     the config driver does), and the run's coverage through depscan's
//     coverage table.
//
// It does no I/O of its own: the runner, the isolation and the file reads
// are injected by the cmd layer (cmd/observer/security_scan_image_trivy.go),
// and the database download is the security.scan.trivy.db lane's
// (internal/secscan/trivydb). imports_test.go pins it free of
// database/sql, net, net/http, os, os/exec and fsnotify.
package trivyimage
