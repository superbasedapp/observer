package secverify

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"text/template"
)

// WorkflowParams are the values the required-workflow template pins.
// Every field is validated against a closed character set before it is
// written into YAML, so no value can break out of its scalar.
type WorkflowParams struct {
	// Version is the observer release tag ("v1.40.0").
	Version string
	// ArchiveSHA256 is the hex SHA-256 of the full-distro linux-x64 archive,
	// taken from the release's SHA256SUMS by the person setting it up.
	ArchiveSHA256 string
	// VendorKey is the base64 Ed25519 vendor public key the archive's .sig
	// must verify against (internal/update/vendorkey.go).
	VendorKey string
	// PolicyRepository is "owner/repo" of the protected repository that
	// holds this workflow and its policy file.
	PolicyRepository string
	// PolicyRef is the full commit SHA of that repository the policy is read
	// at.
	PolicyRef string
	// PolicyPath is the policy file's path inside that repository.
	PolicyPath string
	// KeysPath is the change record keys file's path inside that
	// repository (`observer security provenance status --export-keys`, or
	// the org's keys file). The workflow passes it to --keys when the file
	// is there; without it the change records are not checked.
	KeysPath string
	// ReleaseBaseURL is where release assets are downloaded from, with no
	// trailing slash.
	ReleaseBaseURL string
	// OrgURL, OrgID and OrgKey switch the template to org mode (lane
	// SEC-F2B): the org server's https base URL, the org id and the org's CI
	// signing public key (base64 Ed25519). All three or none. Org mode adds
	// a commits job (no secrets) and a fetch job (the CI credential, from the
	// OBSERVER_CI_CREDENTIAL secret, no checkout of the pull request), and
	// the verdict job reads the org's signed policy instead of the policy
	// file.
	OrgURL, OrgID, OrgKey string
	// ResultUpload (org mode only, lane GATES-SEC) adds the separate result
	// job: after the verdict job, with only the CI credential and its own
	// GitHub Actions OIDC token (`id-token: write` on that job only), it
	// reads the verdict job's SARIF artifact and posts the verdict to the
	// org, which the org's GitHub App turns into the superbased/security
	// status; and the register job, which posts `pending` when the run
	// starts (the same credential and token grant, nothing else). Their
	// failure is a warning; every other job renders byte-identical.
	ResultUpload bool
}

// ExampleOrgWorkflowParams are the placeholder values of the documented org
// mode example: the org key is all zeros, so the example fails closed until
// the org's real key is filled in.
func ExampleOrgWorkflowParams(vendorKey string) WorkflowParams {
	p := ExampleWorkflowParams(vendorKey)
	p.OrgURL = "https://observer-org.example.com"
	p.OrgID = "your-org-id"
	p.OrgKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	return p
}

// DefaultPolicyPath is the policy file's path in the protected repository
// the documented example uses.
const DefaultPolicyPath = "observer-security-ci.toml"

// DefaultKeysPath is the keys file's default path in the protected
// repository.
const DefaultKeysPath = "observer-change-keys.json"

// DefaultReleaseBaseURL is the public release download base.
const DefaultReleaseBaseURL = "https://github.com/superbasedapp/observer/releases/download"

// ExampleWorkflowParams are the placeholder values the documented example
// file is rendered from (docs/examples/security-verify/). The digest and
// policy ref are all zeros so the example fails closed until a real value
// is filled in.
func ExampleWorkflowParams(vendorKey string) WorkflowParams {
	return WorkflowParams{
		Version:          "v0.0.0",
		ArchiveSHA256:    strings.Repeat("0", 64),
		VendorKey:        vendorKey,
		PolicyRepository: "your-org/observer-security-policy",
		PolicyRef:        strings.Repeat("0", 40),
		PolicyPath:       DefaultPolicyPath,
		KeysPath:         DefaultKeysPath,
		ReleaseBaseURL:   DefaultReleaseBaseURL,
	}
}

var (
	tagRE     = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)
	sha256RE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitRE  = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	repoRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$`)
	relPathRE = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,200}$`)
	httpsRE   = regexp.MustCompile(`^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$`)
	orgIDRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// ErrWorkflowParams wraps every refused template value.
var ErrWorkflowParams = errors.New("secverify: workflow template value refused")

// Validate checks every value against its closed shape.
func (p WorkflowParams) Validate() error {
	check := func(name, v string, re *regexp.Regexp) error {
		if !re.MatchString(v) {
			return fmt.Errorf("%w: %s %q", ErrWorkflowParams, name, clipSafe(v, 80))
		}
		return nil
	}
	if err := check("version", p.Version, tagRE); err != nil {
		return err
	}
	if err := check("archive sha256 (64 lowercase hex)", p.ArchiveSHA256, sha256RE); err != nil {
		return err
	}
	if p.VendorKey == "" {
		return fmt.Errorf("%w: no vendor key: pass the base64 Ed25519 vendor public key", ErrWorkflowParams)
	}
	if k, err := base64.StdEncoding.DecodeString(p.VendorKey); err != nil || len(k) != 32 {
		return fmt.Errorf("%w: vendor key is not a base64 Ed25519 public key", ErrWorkflowParams)
	}
	if err := check("policy repository (owner/repo)", p.PolicyRepository, repoRE); err != nil {
		return err
	}
	if err := check("policy ref (full commit SHA)", p.PolicyRef, commitRE); err != nil {
		return err
	}
	if err := check("policy path", p.PolicyPath, relPathRE); err != nil {
		return err
	}
	if ValidRelPath(p.PolicyPath) != nil {
		return fmt.Errorf("%w: policy path %q", ErrWorkflowParams, clipSafe(p.PolicyPath, 80))
	}
	if err := check("keys path", p.KeysPath, relPathRE); err != nil {
		return err
	}
	if ValidRelPath(p.KeysPath) != nil {
		return fmt.Errorf("%w: keys path %q", ErrWorkflowParams, clipSafe(p.KeysPath, 80))
	}
	if err := check("release base URL (https, no trailing slash)", strings.TrimSuffix(p.ReleaseBaseURL, "/"), httpsRE); err != nil {
		return err
	}
	return p.validateOrg(check)
}

// validateOrg checks the org mode values: none, or all three well formed.
func (p WorkflowParams) validateOrg(check func(name, v string, re *regexp.Regexp) error) error {
	if p.OrgURL == "" && p.OrgID == "" && p.OrgKey == "" {
		if p.ResultUpload {
			return fmt.Errorf("%w: the result upload needs org mode (--org-url, --org-id and --org-key)", ErrWorkflowParams)
		}
		return nil
	}
	if err := check("org URL (https, no trailing slash)", p.OrgURL, httpsRE); err != nil {
		return err
	}
	if strings.HasSuffix(p.OrgURL, "/") {
		return fmt.Errorf("%w: org URL ends with a slash", ErrWorkflowParams)
	}
	if err := check("org id", p.OrgID, orgIDRE); err != nil {
		return err
	}
	if k, err := base64.StdEncoding.Strict().DecodeString(p.OrgKey); err != nil || len(k) != 32 {
		return fmt.Errorf("%w: org key is not a base64 Ed25519 public key", ErrWorkflowParams)
	}
	return nil
}

// Archive is the release asset the workflow fetches: the full distro for
// linux-x64 (security plan 4.3: CI runs a pinned, signed full-distro
// artifact).
func (p WorkflowParams) Archive() string {
	return "observer-" + p.Version + "-linux-x64.tar.gz"
}

// Pinned third-party actions, each by full commit SHA with its tag in a
// comment (security plan 7.9: "Third-party actions are pinned by commit
// SHA"). Resolved with `git ls-remote` on 2026-10-20; the setup guide says
// how to refresh them.
const (
	pinCheckout         = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
	pinUploadArtifact   = "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2"
	pinDownloadArtifact = "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2"
	pinUploadSARIF      = "github/codeql-action/upload-sarif@6f2ac81f5cd81fe351a197ba0b00d91d03cd2aee # v4.39.0"
)

// releaseStep fetches the pinned release and checks its digest and vendor
// signature; every job of the workflow that runs observer starts with it.
const releaseStep = `{{define "release"}}      - name: Fetch and verify the pinned observer release
        env:
          VERIFY_RELEASES: {{.ReleaseBaseURL}}
          VERIFY_VERSION: {{.Version}}
          VERIFY_ARCHIVE: {{.Archive}}
          VERIFY_SHA256: {{.ArchiveSHA256}}
          VERIFY_VENDOR_KEY: {{.VendorKey}}
        run: |
          set -euo pipefail
          dir="$RUNNER_TEMP/observer"
          mkdir -p "$dir"
          cd "$dir"
          curl -fsSL --proto '=https' --tlsv1.2 -o "$VERIFY_ARCHIVE" "$VERIFY_RELEASES/$VERIFY_VERSION/$VERIFY_ARCHIVE"
          curl -fsSL --proto '=https' --tlsv1.2 -o "$VERIFY_ARCHIVE.sig" "$VERIFY_RELEASES/$VERIFY_VERSION/$VERIFY_ARCHIVE.sig"
          echo "$VERIFY_SHA256  $VERIFY_ARCHIVE" | sha256sum --check --strict -
          test "$(stat -c %s "$VERIFY_ARCHIVE.sig")" = 64
          printf '%s\n' '-----BEGIN PUBLIC KEY-----' "MCowBQYDK2VwAyEA$VERIFY_VENDOR_KEY" '-----END PUBLIC KEY-----' > vendor.pem
          openssl pkeyutl -verify -pubin -inkey vendor.pem -rawin -in "$VERIFY_ARCHIVE" -sigfile "$VERIFY_ARCHIVE.sig"
          tar -xzf "$VERIFY_ARCHIVE" observer
          ./observer --version
{{end}}`

var workflowTmpl = template.Must(template.Must(template.New("workflow").Parse(releaseStep)).Parse(`# observer security verify: the required workflow (security pillar plan 7.9,
# phase F1 "verify-lite"). Generated by ` + "`observer security verify template`" + `;
# see docs/security-verify.md for setup.
#
# WHEN THIS CHECK BINDS. It binds only when this file lives in a separate,
# protected repository ({{.PolicyRepository}}) and an organization ruleset runs
# it as a REQUIRED WORKFLOW on the repositories it guards: a pull request
# cannot then edit the job, its binary or its policy. Copied into the
# repository under test it is ADVISORY ONLY: a pull request can rewrite it
# under the same job name.
#
# What it does: the verdict job checks out the pull request as data (it never
# runs anything from it), fetches the observer release pinned below by version,
# SHA-256 and vendor Ed25519 signature, reads the policy from the protected
# repository at a pinned commit, and runs ` + "`observer security verify`" + `. It holds
# no secrets and a read-only token. It also fetches the AI change record notes
# (refs/notes/observer) and checks them against the keys file kept in the
# protected repository. The upload job only consumes the verdict job's SARIF
# artifact. A fork pull request's upload may fail on a private repository (its
# token cannot write code scanning there); on a public one it went through in
# the live run. Either way an upload failure is a warning, never the verdict.
{{- if .OrgURL}}
#
# ORG MODE (org {{.OrgID}} at {{.OrgURL}}). Two more jobs run first, so the CI
# credential never shares a job with the pull request's code: the commits job
# (no secrets) lists the pull request's commits; the fetch job (the
# OBSERVER_CI_CREDENTIAL secret, no checkout of the pull request) fetches the
# org's signed CI policy and asks for the commits' change records, waiting a
# bounded time for records still on their way. The verdict job checks both
# documents against the org key pinned below and reads the policy from the org,
# not from a policy file. A fork pull request gets no secrets, so its fetch
# fails and the verdict is unknown (fail closed): keep the keys-file mode for a
# repository that takes fork pull requests.
{{- end}}
name: observer-security-verify

on:
  pull_request:
  merge_group:

permissions: {}

jobs:
{{if .OrgURL}}  commits:
    name: list the commits (no secrets)
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    permissions:
      contents: read
    steps:
      - name: Check out the change as data
        uses: {{.PinCheckout}}
        with:
          ref: ${{"{{"}} github.event.pull_request.head.sha || github.event.merge_group.head_sha {{"}}"}}
          fetch-depth: 0
          persist-credentials: false
          path: target

{{template "release" .}}
      - name: Write the lookup request
        env:
          VERIFY_BASE: ${{"{{"}} github.event.pull_request.base.sha || github.event.merge_group.base_sha {{"}}"}}
          VERIFY_HEAD: ${{"{{"}} github.event.pull_request.head.sha || github.event.merge_group.head_sha {{"}}"}}
        run: |
          set -euo pipefail
          "$RUNNER_TEMP/observer/observer" security verify commits \
            --repo target \
            --base "$VERIFY_BASE" \
            --head "$VERIFY_HEAD" \
            --out observer-change-commits.json

      - name: Keep the request for the fetch job
        uses: {{.PinUploadArtifact}}
        with:
          name: observer-change-commits
          path: observer-change-commits.json
          retention-days: 1

  fetch:
    name: fetch the org's CI policy and change records
    needs: commits
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    permissions: {}
    steps:
{{template "release" .}}
      - name: Fetch the lookup request
        uses: {{.PinDownloadArtifact}}
        with:
          name: observer-change-commits

      - name: Fetch from the org (bounded wait, then unknown_provenance)
        env:
          OBSERVER_CI_CREDENTIAL: ${{"{{"}} secrets.OBSERVER_CI_CREDENTIAL {{"}}"}}
          VERIFY_ORG_URL: {{.OrgURL}}
        run: |
          set -euo pipefail
          "$RUNNER_TEMP/observer/observer" security verify fetch \
            --org-url "$VERIFY_ORG_URL" \
            --commits observer-change-commits.json \
            --policy-out observer-ci-policy.json \
            --lookup-out observer-ci-lookup.json

      - name: Keep the org documents for the verdict job
        uses: {{.PinUploadArtifact}}
        with:
          name: observer-org-documents
          path: |
            observer-ci-policy.json
            observer-ci-lookup.json
          if-no-files-found: ignore
          retention-days: 1

{{end}}  verify:
    name: observer security verify
{{- if .OrgURL}}
    needs: fetch
    # Runs even when the fetch failed: with no org policy it exits unknown,
    # never a skipped (passing) check.
    if: always()
{{- end}}
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    permissions:
      contents: read
    steps:
      - name: Check out the change as data
        uses: {{.PinCheckout}}
        with:
          ref: ${{"{{"}} github.event.pull_request.head.sha || github.event.merge_group.head_sha {{"}}"}}
          fetch-depth: 0
          persist-credentials: false
          path: target

{{if .OrgURL}}      - name: Fetch the org documents
        uses: {{.PinDownloadArtifact}}
        with:
          name: observer-org-documents
          path: ${{"{{"}} runner.temp {{"}}"}}/org-documents
{{else}}      - name: Check out the protected policy
        uses: {{.PinCheckout}}
        with:
          repository: {{.PolicyRepository}}
          ref: {{.PolicyRef}}
          persist-credentials: false
          path: policy
{{end}}
      - name: Fetch the AI change record notes
        env:
          VERIFY_TOKEN: ${{"{{"}} github.token {{"}}"}}
        run: |
          set -euo pipefail
          auth="$(printf 'x-access-token:%s' "$VERIFY_TOKEN" | base64 -w0)"
          if git -C target -c "http.extraheader=AUTHORIZATION: basic $auth" fetch --no-tags --quiet origin '+refs/notes/observer:refs/notes/observer'; then
            echo "change record notes fetched"
          else
            echo "::notice::no refs/notes/observer on this repository: every commit reads unknown_provenance"
          fi

{{template "release" .}}
      - name: Verify the change
        env:
          VERIFY_BASE: ${{"{{"}} github.event.pull_request.base.sha || github.event.merge_group.base_sha {{"}}"}}
          VERIFY_HEAD: ${{"{{"}} github.event.pull_request.head.sha || github.event.merge_group.head_sha {{"}}"}}
{{- if .OrgURL}}
          VERIFY_ORG_ID: {{.OrgID}}
          VERIFY_ORG_KEY: {{.OrgKey}}
        run: |
          set -euo pipefail
          docs="$RUNNER_TEMP/org-documents"
          "$RUNNER_TEMP/observer/observer" security verify \
            --repo target \
            --base "$VERIFY_BASE" \
            --head "$VERIFY_HEAD" \
            --org-policy "$docs/observer-ci-policy.json" \
            --org-lookup "$docs/observer-ci-lookup.json" \
            --org-key "$VERIFY_ORG_KEY" \
            --org-id "$VERIFY_ORG_ID" \
            --sarif observer-security.sarif
{{- else}}
        run: |
          set -euo pipefail
          keys=()
          if [ -f "policy/{{.KeysPath}}" ]; then
            keys=(--keys "policy/{{.KeysPath}}")
          fi
          "$RUNNER_TEMP/observer/observer" security verify \
            --repo target \
            --base "$VERIFY_BASE" \
            --head "$VERIFY_HEAD" \
            --policy "policy/{{.PolicyPath}}" \
            "${keys[@]}" \
            --sarif observer-security.sarif
{{- end}}

      - name: Keep the SARIF for the upload job
        if: always()
        uses: {{.PinUploadArtifact}}
        with:
          name: observer-security-sarif
          path: observer-security.sarif
          if-no-files-found: ignore
          retention-days: 7

  upload:
    name: upload SARIF to code scanning
    needs: verify
    if: always() && needs.verify.result != 'skipped'
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    permissions:
      security-events: write
      # code scanning's upload reads the run's metadata in a private
      # repository; neither grant can write anything.
      actions: read
      contents: read
    steps:
      - name: Fetch the verdict job's SARIF
        id: fetch
        continue-on-error: true
        uses: {{.PinDownloadArtifact}}
        with:
          name: observer-security-sarif

      - name: Upload to code scanning (a fork PR may fail here on a private repository; a warning, never the verdict)
        if: steps.fetch.outcome == 'success'
        continue-on-error: true
        uses: {{.PinUploadSARIF}}
        with:
          sarif_file: observer-security.sarif
          category: observer-security-verify
{{- if .ResultUpload}}

  result:
    # The result upload (org.security.githubapp): reads the verdict job's
    # SARIF only and posts its verdict to the org, whose GitHub App sets the
    # superbased/security commit status. It holds the CI credential and a
    # GitHub Actions OIDC token (id-token: write, this job and the register
    # job only): the org stores the verdict only when the token names this
    # repository, this commit and this policy workflow, and takes the run
    # attempt from the token. Its failure is a warning, never the verdict.
    # On a pull_request run GitHub's token names the merge commit it built
    # for refs/pull/<n>/merge; the org's App checks that commit's two
    # parents and the pull request's head, then posts on the head.
    name: upload the verdict to the org
    needs: verify
    if: always() && needs.verify.result != 'skipped'
    continue-on-error: true
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    permissions:
      id-token: write
    steps:
{{template "release" .}}
      - name: Fetch the verdict job's SARIF
        id: fetch
        continue-on-error: true
        uses: {{.PinDownloadArtifact}}
        with:
          name: observer-security-sarif

      - name: Upload the verdict (no SARIF uploads unknown; a warning, never the verdict)
        env:
          OBSERVER_CI_CREDENTIAL: ${{"{{"}} secrets.OBSERVER_CI_CREDENTIAL {{"}}"}}
          VERIFY_ORG_URL: {{.OrgURL}}
          VERIFY_BASE: ${{"{{"}} github.event.pull_request.base.sha || github.event.merge_group.base_sha {{"}}"}}
          VERIFY_HEAD: ${{"{{"}} github.event.pull_request.head.sha || github.event.merge_group.head_sha {{"}}"}}
        run: |
          set -euo pipefail
          "$RUNNER_TEMP/observer/observer" security verify \
            --upload observer-security.sarif \
            --org-url "$VERIFY_ORG_URL" \
            --base "$VERIFY_BASE" \
            --head "$VERIFY_HEAD"

  register:
    # Registers the run as pending when it starts (no needs): the org's
    # status reads pending, then error if the result job's verdict does not
    # arrive within the org's bounded wait. The CI credential and the OIDC
    # token only; no checkout. Its failure is a warning, never the verdict.
    name: register the run with the org
    continue-on-error: true
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    permissions:
      id-token: write
    steps:
{{template "release" .}}
      - name: Register the run as pending (a warning, never the verdict)
        env:
          OBSERVER_CI_CREDENTIAL: ${{"{{"}} secrets.OBSERVER_CI_CREDENTIAL {{"}}"}}
          VERIFY_ORG_URL: {{.OrgURL}}
          VERIFY_BASE: ${{"{{"}} github.event.pull_request.base.sha || github.event.merge_group.base_sha {{"}}"}}
          VERIFY_HEAD: ${{"{{"}} github.event.pull_request.head.sha || github.event.merge_group.head_sha {{"}}"}}
        run: |
          set -euo pipefail
          "$RUNNER_TEMP/observer/observer" security verify \
            --upload-pending \
            --org-url "$VERIFY_ORG_URL" \
            --base "$VERIFY_BASE" \
            --head "$VERIFY_HEAD"
{{- end}}
`))

// RenderWorkflow renders the required-workflow template with p's values.
func RenderWorkflow(p WorkflowParams) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	data := struct {
		WorkflowParams
		Archive, PinCheckout, PinUploadArtifact, PinDownloadArtifact, PinUploadSARIF string
	}{p, p.Archive(), pinCheckout, pinUploadArtifact, pinDownloadArtifact, pinUploadSARIF}
	data.ReleaseBaseURL = strings.TrimSuffix(p.ReleaseBaseURL, "/")
	if err := workflowTmpl.Execute(&b, data); err != nil {
		return "", fmt.Errorf("secverify.RenderWorkflow: %w", err)
	}
	return b.String(), nil
}
