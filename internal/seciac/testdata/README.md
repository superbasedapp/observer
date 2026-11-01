# seciac test fixtures

- `trivy-0.75.0-config-help.txt` and `kics-2.2.0-scan-help.txt`: the `--help`
  of the pinned versions (Trivy `config --help`, KICS `scan --help`),
  captured from source builds of the two tags fetched through the Go module
  proxy (`go install github.com/aquasecurity/trivy/cmd/trivy@v0.75.0`,
  `go install github.com/Checkmarx/kics/v2/cmd/console@v2.2.0`), because the
  lane's sandbox could not download the vendors' release assets. A source
  build prints `dev` (Trivy) or `development` (KICS) as its version; the
  flag lists are the tags' own. The home directory in Trivy's defaults was
  rewritten to `~`.
- `trivy-0.75.0-config.sarif` and `kics-2.2.0-scan.sarif`: what those two
  builds wrote for the `project/` tree with the driver's own argument list
  (Trivy's embedded checks, `--skip-check-update`; KICS's queries from the
  v2.2.0 module). Trivy's `originalUriBaseIds` was rewritten to
  `file:///work/project/`.
- `project/`: the scanned tree (a Dockerfile with no USER, a privileged
  pod, a public-read S3 bucket).
