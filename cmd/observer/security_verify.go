//go:build !sbo_omit_security

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/secchange"
	"github.com/marmutapp/superbased-observer/internal/secciwf"
	"github.com/marmutapp/superbased-observer/internal/secverify"
)

// security_verify.go is `observer security verify`, the CI verify-lite
// check (security pillar plan 7.9, phase F1). This file is the I/O half:
// it reads the change through gitview's read-only envelope (no hooks, no
// fsmonitor, no pager, no textconv, no external diff) and hands the bytes
// to internal/secverify, which decides.
//
// Hermetic mode: verify never calls config.Load and reads no OBSERVER_*
// variable, no project config, no database and nothing from the PR head
// except the diff as data. That includes the component verb gate, which
// would load the config and the governed component state before the verb
// runs: `security verify` is a gateExempt path (components_gate.go), so the
// gate never wraps it. The policy comes only from --policy (a file outside the
// repository under test: the required workflow's own protected checkout),
// from --policy-from-base (the BASE commit, labelled advisory), or from the
// built-in defaults. The git variables that could point git at another
// repository, object store or diff program are removed from this process
// before git runs (verifyIgnoredGitEnv).

const (
	verifyGitTimeout     = 2 * time.Minute
	verifyNameStatusCap  = 8 << 20
	verifyPatchCap       = 64 << 20
	verifyPolicyReadSize = secverify.MaxPolicyBytes + 1
)

// verifyRevRE is the accepted shape of --base / --head: a hex commit id.
// Refs and expressions are refused so no value can reach git as an option.
var verifyRevRE = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

// verifyIgnoredGitEnv lists the git variables hermetic mode removes: each
// would let the environment redirect what git reads or run a program
// (git-scm.com/docs/git#_environment_variables).
var verifyIgnoredGitEnv = []string{
	"GIT_DIR",
	"GIT_WORK_TREE",
	"GIT_COMMON_DIR",
	"GIT_INDEX_FILE",
	"GIT_OBJECT_DIRECTORY",
	"GIT_ALTERNATE_OBJECT_DIRECTORIES",
	"GIT_NAMESPACE",
	"GIT_CEILING_DIRECTORIES",
	"GIT_DISCOVERY_ACROSS_FILESYSTEM",
	"GIT_CONFIG",
	"GIT_CONFIG_GLOBAL",
	"GIT_CONFIG_SYSTEM",
	"GIT_CONFIG_NOSYSTEM",
	"GIT_CONFIG_PARAMETERS",
	"GIT_CONFIG_COUNT",
	"GIT_EXTERNAL_DIFF",
	"GIT_DIFF_OPTS",
	"GIT_REPLACE_REF_BASE",
	"GIT_NO_REPLACE_OBJECTS",
	"GIT_GRAFT_FILE",
	"GIT_SHALLOW_FILE",
	"GIT_EXEC_PATH",
	"GIT_NOTES_REF",
	"GIT_NOTES_DISPLAY_REF",
	"GIT_NOTES_REWRITE_REF",
}

// verifyDiffFlags are the flags every diff verify runs carries: renames off
// (a rename is judged as a delete plus an add), no external diff, no
// textconv, no color and explicit prefixes; verifyGitPrefix pins relative
// mode off (git 2.25 has no --no-relative), so repository config cannot
// reshape the output the parser reads.
// verifyGitPrefix comes before the diff subcommand: command-line config
// overrides the repository's diff.relative on every git version.
var verifyGitPrefix = []string{"-c", "diff.relative=false"}

var verifyDiffFlags = []string{
	"--no-color", "--no-ext-diff", "--no-textconv", "--no-renames",
	"--src-prefix=a/", "--dst-prefix=b/", "--ignore-submodules=none",
}

type securityVerifyOpts struct {
	repo, base, head     string
	policyFile, baseFile string
	sarif                string
	installIndex         string
	keys                 string
	provenanceJSON       string
	// Org mode (security_verify_org.go).
	orgPolicy, orgLookup string
	orgKey, orgID        string
	minPolicyVersion     int64
	upload               verifyUploadOpts // --upload (security_verify_upload.go)
}

// newSecurityVerifyCmd builds `observer security verify`.
func newSecurityVerifyCmd() *cobra.Command {
	var o securityVerifyOpts
	cmd := &cobra.Command{
		Use:   "verify --base <sha> --head <sha>",
		Short: "Check a pull request's change in CI (headless, hermetic)",
		Long: `Check the change between two commits the way the required CI workflow does:
secrets added by the change and agent configuration files it adds or changes,
with the policy taken only from a protected source. The change is read as data
and nothing in it is run.

Exit codes: 0 pass, 1 a finding the policy denies, 2 unknown (the change could
not be read in full, a required detector did not finish, or any error: fail
closed), 3 the security module is not in this build. No configuration on the
runner can refuse the check: it is exempt from the component gate.

With --org-policy (org mode) the policy, the change record keys and the
records themselves come from the org's signed documents, which
` + "`verify commits`" + ` and ` + "`verify fetch`" + ` prepare in separate jobs.

See docs/security-verify.md for the required-workflow setup and when the check
binds.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			err := runSecurityVerify(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), o)
			var ec exitErr
			if errors.As(err, &ec) {
				// The summary or the UNKNOWN line already said why; the exit
				// code is the whole signal, with no cobra error banner.
				cmd.SilenceErrors = true
				if r := cmd.Root(); r != nil {
					r.SilenceErrors = true
				}
			}
			return err
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.repo, "repo", ".", "the repository under test (a git work tree with base and head fetched)")
	f.StringVar(&o.base, "base", "", "base commit (hex); the change is base...head (from their merge base)")
	f.StringVar(&o.head, "head", "", "head commit (hex)")
	f.StringVar(&o.policyFile, "policy", "", "policy file OUTSIDE the repository under test (the protected checkout)")
	f.StringVar(&o.baseFile, "policy-from-base", "", "read the policy from this path at the BASE commit (advisory setups only)")
	f.StringVar(&o.sarif, "sarif", "", "write SARIF 2.1.0 to this file")
	f.StringVar(&o.installIndex, "install-index", "", "a signed install index directory (the content channel layout, outside the repository under test) for the install_index detector")
	f.StringVar(&o.keys, "keys", "", "a keys file (outside the repository under test) to check the commits' signed AI change records against; fetch refs/notes/observer first")
	f.StringVar(&o.provenanceJSON, "provenance-json", "", "write the change record outcomes and the squash statement as JSON to this file")
	addVerifyOrgFlags(f, &o)
	addVerifyUploadFlags(f, &o.upload)
	cmd.AddCommand(newSecurityVerifyTemplateCmd(), newSecurityVerifyCommitsCmd(), newSecurityVerifyFetchCmd())
	return cmd
}

// verifyFail prints a one-line reason and returns the unknown exit code.
func verifyFail(stderr io.Writer, format string, args ...any) error {
	fmt.Fprintf(stderr, "observer security verify: UNKNOWN: "+format+"\n", args...)
	return exitErr(secverify.ExitUnknown)
}

func runSecurityVerify(ctx context.Context, stdout, stderr io.Writer, o securityVerifyOpts) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if o.upload.active() {
		return runSecurityVerifyUpload(ctx, stdout, stderr, o)
	}
	if why := verifyArgsRefusal(o); why != "" {
		return verifyFail(stderr, "%s", why)
	}
	var dropped []string
	for _, k := range verifyIgnoredGitEnv {
		if _, ok := os.LookupEnv(k); ok {
			_ = os.Unsetenv(k)
			dropped = append(dropped, k)
		}
	}
	if len(dropped) > 0 {
		fmt.Fprintf(stderr, "observer security verify: hermetic mode ignored %s\n", strings.Join(dropped, ", "))
	}

	repoAbs, err := filepath.Abs(o.repo)
	if err != nil {
		return verifyFail(stderr, "repository path: %v", err)
	}
	top, _, err := gitview.RunReadOnlyTimeout(ctx, repoAbs, 4096, verifyGitTimeout, "rev-parse", "--show-toplevel")
	if err != nil {
		return verifyFail(stderr, "%s is not a git work tree: %v", secverify.QuotePath(o.repo), err)
	}
	root := strings.TrimSpace(string(top))
	base, err := resolveVerifyCommit(ctx, root, o.base)
	if err != nil {
		return verifyFail(stderr, "base %s: %v", o.base, err)
	}
	head, err := resolveVerifyCommit(ctx, root, o.head)
	if err != nil {
		return verifyFail(stderr, "head %s: %v", o.head, err)
	}

	var org *verifyOrg
	var pol secverify.Policy
	if o.orgPolicy != "" {
		if org, err = loadVerifyOrg(root, o, time.Now()); err != nil {
			return verifyFail(stderr, "org policy: %v", err)
		}
		pol = org.policy.Policy
	} else if pol, err = loadVerifyPolicy(ctx, root, base, o); err != nil {
		return verifyFail(stderr, "policy: %v", err)
	}

	req := secverify.Request{Policy: pol, Base: base, Head: head}
	if o.installIndex != "" {
		if inside, ierr := pathInside(root, o.installIndex); ierr != nil || inside {
			return verifyFail(stderr, "--install-index must be outside the repository under test")
		}
		dc, derr := verifyDependencyCheck(o.installIndex)
		if derr != nil {
			return verifyFail(stderr, "install index: %v", derr)
		}
		req.Dependencies = dc
	}
	if req.Provenance, err = verifyProvenanceInput(ctx, root, base, head, o.keys, org); err != nil {
		return verifyFail(stderr, "change records: %v", err)
	}
	rng := base + "..." + head
	ns, nsOver, err := gitview.RunReadOnlyTimeout(ctx, root, verifyNameStatusCap, verifyGitTimeout,
		append(append(append(append([]string{}, verifyGitPrefix...), "diff", "--name-status", "-z"), verifyDiffFlags...), rng, "--")...)
	if err != nil {
		req.ReadErr = fmt.Errorf("git diff --name-status: %w", err)
	}
	var patch []byte
	var patchOver bool
	if req.ReadErr == nil {
		patch, patchOver, err = gitview.RunReadOnlyTimeout(ctx, root, verifyPatchCap, verifyGitTimeout,
			append(append(append(append([]string{}, verifyGitPrefix...), "diff", "-U0", "--text"), verifyDiffFlags...), rng, "--")...)
		if err != nil {
			req.ReadErr = fmt.Errorf("git diff: %w", err)
		}
	}
	req.NameStatus, req.Patch, req.Truncated = ns, patch, nsOver || patchOver
	// The ci_workflow detector reads a changed workflow whole as it is at
	// head: the raw blob (cat-file applies no textconv or filter), capped
	// one byte past the workflow rules' cap so "over" is reported, never
	// cut. The path is one the parsed name list validated.
	req.ReadHead = func(path string) ([]byte, bool, error) {
		return gitview.RunReadOnlyTimeout(ctx, root, secciwf.MaxWorkflowBytes+1, verifyGitTimeout,
			append(append([]string{}, verifyGitPrefix...), "cat-file", "blob", head+":"+path)...)
	}

	rep := secverify.Verify(ctx, req, nil)
	if o.sarif != "" {
		var buf bytes.Buffer
		toolVersion := ""
		if verifyTagRE.MatchString(version) {
			// A development build's "dev" is not a version code scanning
			// should record.
			toolVersion = version
		}
		if err := secverify.WriteSARIF(&buf, rep, filepath.ToSlash(root), toolVersion); err != nil {
			return verifyFail(stderr, "SARIF: %v", err)
		}
		if err := os.WriteFile(o.sarif, buf.Bytes(), 0o600); err != nil {
			return verifyFail(stderr, "write SARIF: %v", err)
		}
	}
	if err := writeVerifyProvenanceJSON(o.provenanceJSON, rep.Provenance); err != nil {
		return verifyFail(stderr, "write the change record outcomes: %v", err)
	}
	if err := secverify.WriteSummary(stdout, rep); err != nil {
		return verifyFail(stderr, "write summary: %v", err)
	}
	if code := rep.Verdict.ExitCode(); code != secverify.ExitPass {
		return exitErr(code)
	}
	return nil
}

// resolveVerifyCommit turns a hex id into the full commit id, refusing
// anything that is not a commit in the repository.
func resolveVerifyCommit(ctx context.Context, root, rev string) (string, error) {
	out, _, err := gitview.RunReadOnlyTimeout(ctx, root, 4096, verifyGitTimeout,
		"rev-parse", "--verify", "--quiet", rev+"^{commit}")
	if err != nil {
		if gitview.IsNoCommitsError(err) {
			return "", errors.New("not a commit in this repository (fetch it: actions/checkout with fetch-depth: 0)")
		}
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// loadVerifyPolicy reads the hermetic policy. A --policy file inside the
// repository under test is refused: the PR controls that tree, so a policy
// there is the PR's, which security plan 7.9 says is always ignored.
func loadVerifyPolicy(ctx context.Context, root, base string, o securityVerifyOpts) (secverify.Policy, error) {
	switch {
	case o.policyFile != "":
		inside, err := pathInside(root, o.policyFile)
		if err != nil {
			return secverify.Policy{}, err
		}
		if inside {
			return secverify.Policy{}, fmt.Errorf("%s is inside the repository under test; the PR controls it. Check the policy out from the protected repository, or use --policy-from-base for an advisory setup", secverify.QuotePath(o.policyFile))
		}
		fh, err := os.Open(o.policyFile)
		if err != nil {
			return secverify.Policy{}, err
		}
		defer fh.Close()
		b, err := io.ReadAll(io.LimitReader(fh, verifyPolicyReadSize))
		if err != nil {
			return secverify.Policy{}, err
		}
		return secverify.ParsePolicy(b, secverify.SourceProtected)
	case o.baseFile != "":
		if err := secverify.ValidRelPath(o.baseFile); err != nil {
			return secverify.Policy{}, err
		}
		b, over, err := gitview.RunReadOnlyTimeout(ctx, root, verifyPolicyReadSize, verifyGitTimeout,
			"cat-file", "blob", base+":"+o.baseFile)
		if err != nil {
			return secverify.Policy{}, fmt.Errorf("read %s at the base commit: %w", secverify.QuotePath(o.baseFile), err)
		}
		if over {
			return secverify.Policy{}, fmt.Errorf("%s at the base commit is over %d bytes", secverify.QuotePath(o.baseFile), secverify.MaxPolicyBytes)
		}
		return secverify.ParsePolicy(b, secverify.SourceBaseCommit)
	}
	return secverify.DefaultPolicy(), nil
}

// pathInside reports whether p resolves inside root (symlinks followed on
// both sides, so a link from outside into the tree is caught).
func pathInside(root, p string) (bool, error) {
	ap, err := filepath.Abs(p)
	if err != nil {
		return false, err
	}
	if rp, err := filepath.EvalSymlinks(ap); err == nil {
		ap = rp
	}
	rr := root
	if r, err := filepath.EvalSymlinks(root); err == nil {
		rr = r
	}
	rel, err := filepath.Rel(rr, ap)
	if err != nil {
		return false, nil
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))), nil
}

// newSecurityVerifyTemplateCmd builds `observer security verify template`,
// which prints the required-workflow template (security plan 7.9 "The
// template generator"; the dashboard's Code security > Evidence > CI check
// renders the same function).
func newSecurityVerifyTemplateCmd() *cobra.Command {
	p := secverify.ExampleWorkflowParams(verifyDefaultVendorKey())
	if v := strings.TrimSpace(version); verifyTagRE.MatchString(v) {
		p.Version = v
	}
	cmd := &cobra.Command{
		Use:   "template --sha256 <archive digest> --policy-repo <owner/repo> --policy-ref <commit>",
		Short: "Print the protected required-workflow template for CI verify",
		Long: `Print the GitHub Actions workflow that runs observer security verify as a
required workflow. Put it in a separate, protected repository together with the
policy file and require it with an organization ruleset; copied into the
repository under test it is advisory only. --sha256 is the SHA-256 of
observer-<version>-linux-x64.tar.gz from the release's SHA256SUMS.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := secverify.RenderWorkflow(p)
			if err != nil {
				return err
			}
			_, err = io.WriteString(cmd.OutOrStdout(), out)
			return err
		},
	}
	f := cmd.Flags()
	f.StringVar(&p.Version, "version", p.Version, "observer release tag to pin")
	f.StringVar(&p.ArchiveSHA256, "sha256", p.ArchiveSHA256, "SHA-256 of the linux-x64 full archive (from SHA256SUMS)")
	f.StringVar(&p.PolicyRepository, "policy-repo", p.PolicyRepository, "the protected repository (owner/repo) holding the workflow and policy")
	f.StringVar(&p.PolicyRef, "policy-ref", p.PolicyRef, "full commit SHA of the protected repository to read the policy at")
	f.StringVar(&p.PolicyPath, "policy-path", p.PolicyPath, "policy file path inside the protected repository")
	f.StringVar(&p.KeysPath, "keys-path", p.KeysPath, "change record keys file path inside the protected repository (passed to --keys when present)")
	f.StringVar(&p.ReleaseBaseURL, "release-base-url", p.ReleaseBaseURL, "release download base (an internal mirror, for example)")
	f.StringVar(&p.VendorKey, "vendor-key", p.VendorKey, "base64 Ed25519 vendor public key the archive signature must verify against")
	f.StringVar(&p.OrgURL, "org-url", "", "org mode: the org server's https base URL (with --org-id and --org-key; adds the commits and fetch jobs)")
	f.StringVar(&p.OrgID, "org-id", "", "org mode: the org id the CI documents must name")
	f.StringVar(&p.OrgKey, "org-key", "", "org mode: the org's CI signing public key (base64 Ed25519), pinned in the workflow")
	f.BoolVar(&p.ResultUpload, "result-upload", false, "org mode: add the separate result job that uploads the verdict for the org's GitHub App (a warning, never the verdict)")
	return cmd
}

// verifyTagRE is a release tag; a development build's version is not one,
// so the template keeps its placeholder.
var verifyTagRE = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)

// verifyProvenanceInput reads the pull request's commits (base..head, merges
// left out) and, for each, its tree, its patch fingerprint, the envelope
// lines of its note under refs/notes/observer and its Assisted-by trailer,
// all as data through the read-only envelope. The keys file must be
// outside the repository under test (the PR controls that tree). In org
// mode the org's keys file is merged with it (either may be absent) and the
// org's lookup answer joins the notes. Neither: nil, the step does not run.
func verifyProvenanceInput(ctx context.Context, root, base, head, keysPath string, org *verifyOrg) (*secverify.ProvenanceInput, error) {
	if keysPath == "" && org == nil {
		return nil, nil
	}
	var trust secchange.TrustSet
	if keysPath != "" {
		b, err := readVerifyOutside(root, keysPath, "the keys file", secchange.MaxTrustFileSize)
		if err != nil {
			return nil, err
		}
		if trust, err = secchange.ParseTrustFile(b); err != nil {
			return nil, err
		}
	}
	in := &secverify.ProvenanceInput{Trust: trust}
	if org != nil {
		in.Trust = org.policy.Trust
		if keysPath != "" {
			in.Trust = org.policy.Trust.Merge(trust)
		}
		in.Org = org.provenance()
	}
	shas, truncated, err := verifyRangeCommits(ctx, root, base, head)
	if err != nil {
		return nil, err
	}
	in.Truncated = truncated
	for _, sha := range shas {
		c := secverify.ProvenanceCommit{Facts: secchange.CommitFacts{SHA: sha}}
		tree, fp, _, ierr := provenanceCommitIdentity(ctx, gitview.RunReadOnlyTimeout, root, sha, "", "")
		if ierr != nil {
			c.ReadErr = "identity"
		}
		c.Facts.Tree, c.Facts.PatchFP = tree, fp
		if note, _, nerr := gitview.RunReadOnlyTimeout(ctx, root, 1<<20, verifyGitTimeout, "notes", "--ref="+secchange.NotesRef, "show", sha); nerr == nil {
			c.Notes = secchange.NoteEnvelopes(note)
		}
		if org != nil {
			// The committer and author, hashed the way the org hashes a
			// certified key's member (lane SEC-P4 decision 8).
			if id, _, ierr := gitview.RunReadOnlyTimeout(ctx, root, 4096, verifyGitTimeout, "log", "-1", "--format=%ae%n%ce", sha); ierr == nil {
				for i, e := range strings.Split(string(id), "\n") {
					if h := orgcontract.ChangeMemberEmailHash(e); h != "" {
						c.IdentityHashes = append(c.IdentityHashes, h)
						if i == 1 {
							c.CommitterHash = h
						}
					}
				}
			}
		}
		if tr, _, terr := gitview.RunReadOnlyTimeout(ctx, root, 4096, verifyGitTimeout, "log", "-1", "--format=%(trailers:key="+secchange.TrailerKey+",valueonly)", sha); terr == nil {
			line, _, _ := strings.Cut(strings.TrimSpace(string(tr)), "\n")
			c.Trailer = strings.TrimSpace(line)
		}
		c.Path = verifyProvenanceAnchor(ctx, root, sha)
		in.Commits = append(in.Commits, c)
	}
	return in, nil
}

// verifyProvenanceAnchor reads what secverify.ProvenanceAnchor picks the
// commit's SARIF location from: the paths the commit changes and, only when
// it changes none, its tree's root entries. "" on a read failure (the
// SARIF writer then uses secverify.ProvenanceFallbackPath).
func verifyProvenanceAnchor(ctx context.Context, root, sha string) string {
	out, over, err := gitview.RunReadOnlyTimeout(ctx, root, 1<<20, verifyGitTimeout,
		"diff-tree", "--no-commit-id", "--name-only", "-r", "--root", "--no-renames", "-z", sha)
	if err != nil {
		return ""
	}
	changed := verifyNULFields(out, over)
	var entries []string
	if len(changed) == 0 {
		if ls, lover, lerr := gitview.RunReadOnlyTimeout(ctx, root, 1<<20, verifyGitTimeout, "ls-tree", "--name-only", "-z", sha); lerr == nil {
			entries = verifyNULFields(ls, lover)
		}
	}
	return secverify.ProvenanceAnchor(changed, entries)
}

// verifyNULFields splits NUL-terminated git output. When over (the output
// was cut at its cap) the last field may be partial and is dropped.
func verifyNULFields(b []byte, over bool) []string {
	parts := strings.Split(string(b), "\x00")
	if last := len(parts) - 1; over || parts[last] == "" {
		parts = parts[:last]
	}
	fields := parts[:0]
	for _, p := range parts {
		if p != "" {
			fields = append(fields, p)
		}
	}
	return fields
}

// verifyArgsRefusal checks the arguments before anything runs: the commit
// ids' shape, the exclusive policy flags, and PT-10 (decision log P-005): a
// file: URI or a Windows drive form on a path argument is refused up front,
// so it exits 2 (unknown) instead of being opened as something the caller
// did not mean.
func verifyArgsRefusal(o securityVerifyOpts) string {
	if !verifyRevRE.MatchString(o.base) || !verifyRevRE.MatchString(o.head) {
		return "--base and --head must be hex commit ids (7 to 64 lowercase hex characters)"
	}
	if o.policyFile != "" && o.baseFile != "" {
		return "--policy and --policy-from-base are exclusive"
	}
	if why := verifyOrgArgsRefusal(o); why != "" {
		return why
	}
	for _, a := range [][2]string{
		{"--repo", o.repo},
		{"--policy", o.policyFile},
		{"--policy-from-base", o.baseFile},
		{"--sarif", o.sarif},
		{"--install-index", o.installIndex},
		{"--keys", o.keys},
		{"--provenance-json", o.provenanceJSON},
		{"--org-policy", o.orgPolicy},
		{"--org-lookup", o.orgLookup},
	} {
		if why := secverify.PathArgRefusal(a[0], a[1], runtime.GOOS == "windows"); why != "" {
			return why
		}
	}
	return ""
}

// writeVerifyProvenanceJSON writes the change record outcomes and the
// squash statement ("" path: nothing).
func writeVerifyProvenanceJSON(path string, p secverify.ProvenanceReport) error {
	if path == "" {
		return nil
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}
