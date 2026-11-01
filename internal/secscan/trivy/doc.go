// Package trivy is the security.scan.trivy driver (security pillar plan
// sections 4.2, 4.4 and 5.6 P2; gap G4; lane GATES-SEC): Trivy's `config`
// subcommand (misconfiguration only, never a vulnerability scan) over a
// project's Dockerfiles, Kubernetes, Terraform, CloudFormation and Helm
// files, run as a separately installed, pinned and signature-checked
// process. The engine table, pins, decision table, argument list and
// SARIF mapping are internal/seciac's; this package is the driver's row
// and its constructor, and trivynet is its one egress lane (the guided
// install's release download). It does no I/O of its own.
package trivy
