//go:build !sbo_omit_security

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/seccifetch"
	"github.com/marmutapp/superbased-observer/internal/secverify"
)

// security_verify_org.go is verify's org mode (security plan 7.9 F2 and
// 7.10, lane SEC-F2B), split over three jobs of the protected workflow so
// the CI credential never shares a job with the pull request's code:
//
//   - `verify commits` (no secrets) lists the pull request's commits with
//     their patch fingerprint hashes, as the lookup request;
//   - `verify fetch` (the CI credential, no checkout of the pull request)
//     fetches the org's signed CI policy and asks for the commits' change
//     records with a bounded wait, then unknown_provenance; it can also
//     fetch a pinned CI driver from the org's security mirror;
//   - `verify --org-policy --org-lookup` (no secrets) checks both documents
//     against the org key the protected workflow pins and decides.
//
// The fetch reads one variable, the credential (--credential-env), and
// nothing else of the runner; verify stays hermetic.

// verifyOrgCredentialEnv is the default variable the fetch reads the CI
// credential from (never a flag: a flag lands in the process list).
const verifyOrgCredentialEnv = "OBSERVER_CI_CREDENTIAL" //nolint:gosec // G101: a variable name, not a credential

// verifyOrgMaxWait bounds --wait (the org's own cap).
const verifyOrgMaxWait = 1800

// addVerifyOrgFlags adds the org mode flags to `verify`.
func addVerifyOrgFlags(f *pflag.FlagSet, o *securityVerifyOpts) {
	f.StringVar(&o.orgPolicy, "org-policy", "", "the org's signed CI policy (written by `verify fetch`, outside the repository under test); replaces --policy")
	f.StringVar(&o.orgLookup, "org-lookup", "", "the org's signed change record lookup answer (written by `verify fetch`); absent: the commits read only their notes")
	f.StringVar(&o.orgKey, "org-key", "", "the org's CI signing public key (base64 Ed25519), pinned in the protected workflow")
	f.StringVar(&o.orgID, "org-id", "", "the org id the documents must name")
	f.Int64Var(&o.minPolicyVersion, "min-policy-version", 0, "refuse an org policy older than this version (a rollback floor)")
}

// verifyOrgArgsRefusal checks the org mode flags' combination.
func verifyOrgArgsRefusal(o securityVerifyOpts) string {
	switch {
	case o.orgPolicy == "" && (o.orgLookup != "" || o.orgKey != "" || o.orgID != "" || o.minPolicyVersion != 0):
		return "--org-lookup, --org-key, --org-id and --min-policy-version need --org-policy"
	case o.orgPolicy == "":
		return ""
	case o.policyFile != "" || o.baseFile != "":
		return "--org-policy carries the policy: it is exclusive with --policy and --policy-from-base"
	case o.orgKey == "" || o.orgID == "":
		return "--org-policy needs --org-key and --org-id (pinned in the protected workflow)"
	case o.minPolicyVersion < 0:
		return "--min-policy-version must not be negative"
	}
	if _, err := parseVerifyOrgKey(o.orgKey); err != nil {
		return err.Error()
	}
	return ""
}

// parseVerifyOrgKey reads the pinned org key.
func parseVerifyOrgKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("--org-key must be a base64 Ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
}

// verifyOrg is a checked org policy and, when it came, lookup answer.
type verifyOrg struct {
	policy secverify.OrgPolicy
	key    ed25519.PublicKey
	lookup *secverify.OrgLookup
}

func (v *verifyOrg) provenance() *secverify.OrgProvenance {
	return &secverify.OrgProvenance{OrgID: v.policy.OrgID, OrgKey: v.key, PolicyVersion: v.policy.Version, Lookup: v.lookup}
}

// loadVerifyOrg reads and checks the org documents. A missing lookup file
// is not an error (the fetch job's wait ran out with no answer); a lookup
// file that does not check is.
func loadVerifyOrg(root string, o securityVerifyOpts, now time.Time) (*verifyOrg, error) {
	key, err := parseVerifyOrgKey(o.orgKey)
	if err != nil {
		return nil, err
	}
	doc, err := readVerifyOutside(root, o.orgPolicy, "the org policy", orgcontract.MaxCIDocumentBytes)
	if err != nil {
		return nil, err
	}
	pol, err := secverify.ParseOrgPolicy(doc, o.orgID, key, o.minPolicyVersion, now)
	if err != nil {
		return nil, err
	}
	v := &verifyOrg{policy: pol, key: key}
	if o.orgLookup == "" {
		return v, nil
	}
	doc, err = readVerifyOutside(root, o.orgLookup, "the org lookup answer", orgcontract.MaxCIDocumentBytes)
	if errors.Is(err, os.ErrNotExist) {
		return v, nil
	}
	if err != nil {
		return nil, err
	}
	if v.lookup, err = secverify.ParseOrgLookup(doc, o.orgID, key, now); err != nil {
		return nil, err
	}
	return v, nil
}

// readVerifyOutside reads a file the caller named, refusing one inside the
// repository under test (the PR controls that tree), capped at max.
func readVerifyOutside(root, path, what string, max int64) ([]byte, error) {
	inside, err := pathInside(root, path)
	if err != nil {
		return nil, err
	}
	if inside {
		return nil, fmt.Errorf("%s %s is inside the repository under test; the PR controls it. Keep it outside the checkout", what, secverify.QuotePath(path))
	}
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s is over %d bytes", what, max)
	}
	return b, nil
}

// verifyRangeCommits lists the pull request's commits (base..head, merges
// left out), at most secverify.MaxProvenanceCommits.
func verifyRangeCommits(ctx context.Context, root, base, head string) ([]string, bool, error) {
	out, _, err := gitview.RunReadOnlyTimeout(ctx, root, 1<<20, verifyGitTimeout,
		"rev-list", "--no-merges", "--max-count="+strconv.Itoa(secverify.MaxProvenanceCommits+1), base+".."+head)
	if err != nil {
		return nil, false, fmt.Errorf("list the commits: %w", err)
	}
	shas := strings.Fields(string(out))
	if len(shas) > secverify.MaxProvenanceCommits {
		return shas[:secverify.MaxProvenanceCommits], true, nil
	}
	return shas, false, nil
}

// verifyHermeticGit removes the git variables verify ignores.
func verifyHermeticGit(stderr io.Writer, verb string) {
	var dropped []string
	for _, k := range verifyIgnoredGitEnv {
		if _, ok := os.LookupEnv(k); ok {
			_ = os.Unsetenv(k)
			dropped = append(dropped, k)
		}
	}
	if len(dropped) > 0 {
		fmt.Fprintf(stderr, "observer security verify %s: hermetic mode ignored %s\n", verb, strings.Join(dropped, ", "))
	}
}

// newSecurityVerifyCommitsCmd builds `observer security verify commits`.
func newSecurityVerifyCommitsCmd() *cobra.Command {
	var repo, base, head, out string
	cmd := &cobra.Command{
		Use:   "commits --base <sha> --head <sha> --out <file>",
		Short: "Write the org lookup request for a pull request's commits (no secrets)",
		Long: `List the commits of base..head (merges left out) with the hash of each one's
patch fingerprint, as the request ` + "`observer security verify fetch`" + ` sends to the
org. Runs in a job that holds no secret; the change is read as data.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			stderr := cmd.ErrOrStderr()
			fail := func(format string, args ...any) error {
				fmt.Fprintf(stderr, "observer security verify commits: UNKNOWN: "+format+"\n", args...)
				cmd.SilenceErrors = true
				if r := cmd.Root(); r != nil {
					r.SilenceErrors = true
				}
				return exitErr(secverify.ExitUnknown)
			}
			if !verifyRevRE.MatchString(base) || !verifyRevRE.MatchString(head) {
				return fail("--base and --head must be hex commit ids (7 to 64 lowercase hex characters)")
			}
			if out == "" {
				return fail("--out is required")
			}
			for _, a := range [][2]string{{"--repo", repo}, {"--out", out}} {
				if why := secverify.PathArgRefusal(a[0], a[1], runtime.GOOS == "windows"); why != "" {
					return fail("%s", why)
				}
			}
			verifyHermeticGit(stderr, "commits")
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			req, err := verifyLookupRequest(ctx, repo, base, head)
			if err != nil {
				return fail("%v", err)
			}
			b, err := json.MarshalIndent(req, "", "  ")
			if err != nil {
				return fail("%v", err)
			}
			if err := writeFileAtomic(out, append(b, '\n')); err != nil {
				return fail("write %s: %v", secverify.QuotePath(out), err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%d commit(s) written\n", len(req.Commits))
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&repo, "repo", ".", "the repository under test")
	f.StringVar(&base, "base", "", "base commit (hex)")
	f.StringVar(&head, "head", "", "head commit (hex)")
	f.StringVar(&out, "out", "", "write the lookup request JSON here")
	return cmd
}

// verifyLookupRequest builds the lookup request for base..head.
func verifyLookupRequest(ctx context.Context, repo, base, head string) (orgcontract.CILookupRequest, error) {
	repoAbs, err := filepath.Abs(repo)
	if err != nil {
		return orgcontract.CILookupRequest{}, err
	}
	top, _, err := gitview.RunReadOnlyTimeout(ctx, repoAbs, 4096, verifyGitTimeout, "rev-parse", "--show-toplevel")
	if err != nil {
		return orgcontract.CILookupRequest{}, fmt.Errorf("%s is not a git work tree: %w", secverify.QuotePath(repo), err)
	}
	root := strings.TrimSpace(string(top))
	if base, err = resolveVerifyCommit(ctx, root, base); err != nil {
		return orgcontract.CILookupRequest{}, fmt.Errorf("base: %w", err)
	}
	if head, err = resolveVerifyCommit(ctx, root, head); err != nil {
		return orgcontract.CILookupRequest{}, fmt.Errorf("head: %w", err)
	}
	shas, _, err := verifyRangeCommits(ctx, root, base, head)
	if err != nil {
		return orgcontract.CILookupRequest{}, err
	}
	req := orgcontract.CILookupRequest{Commits: []orgcontract.CILookupCommit{}}
	for _, sha := range shas {
		c := orgcontract.CILookupCommit{SHA: sha}
		if _, fp, _, ierr := provenanceCommitIdentity(ctx, gitview.RunReadOnlyTimeout, root, sha, "", ""); ierr == nil {
			c.PatchFPHash = orgcontract.ChangePatchFPHash(fp)
		}
		req.Commits = append(req.Commits, c)
	}
	return req, nil
}

// writeFileAtomic writes b to path (0600) through a temporary file beside
// it.
func writeFileAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".observer-verify-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

// verifyDriverRE is one --driver: kind/name=sha256.
var verifyDriverRE = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]{0,127})/([A-Za-z0-9][A-Za-z0-9._-]{0,127})=([0-9a-f]{64})$`)

type securityVerifyFetchOpts struct {
	orgURL, commits, policyOut, lookupOut string
	credentialEnv                         string
	wait                                  int
	drivers                               []string
	driverDir, driverOS, driverArch       string
}

// newSecurityVerifyFetchCmd builds `observer security verify fetch`.
func newSecurityVerifyFetchCmd() *cobra.Command {
	o := securityVerifyFetchOpts{credentialEnv: verifyOrgCredentialEnv, wait: -1, driverOS: runtime.GOOS, driverArch: runtime.GOARCH}
	cmd := &cobra.Command{
		Use:   "fetch --org-url <url> --commits <file> --policy-out <file> --lookup-out <file>",
		Short: "Fetch the org's CI policy and change records with the CI credential",
		Long: `Fetch the org's signed CI policy and ask for the change records of the
commits ` + "`verify commits`" + ` listed, waiting a bounded time (the policy's wait, or
--wait seconds, with backoff) for records still on their way. A commit with no
record when the wait runs out reads as unknown_provenance. Run it in a job that
holds the CI credential (in the variable --credential-env names) and never
checks out the pull request. Nothing fetched is trusted here: verify checks
the signatures against the org key the protected workflow pins.

--driver kind/name=sha256 also downloads a CI driver from the org's security
mirror into --driver-dir, refusing it unless its SHA-256 is the pin.

Exit codes: 0 fetched (the lookup may still be missing: a warning says so),
2 the policy or a driver could not be fetched (fail closed).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			err := runSecurityVerifyFetch(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), o)
			var ec exitErr
			if errors.As(err, &ec) {
				cmd.SilenceErrors = true
				if r := cmd.Root(); r != nil {
					r.SilenceErrors = true
				}
			}
			return err
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.orgURL, "org-url", "", "the org server's base URL (https)")
	f.StringVar(&o.commits, "commits", "", "the lookup request `verify commits` wrote")
	f.StringVar(&o.policyOut, "policy-out", "", "write the signed CI policy here")
	f.StringVar(&o.lookupOut, "lookup-out", "", "write the signed lookup answer here")
	f.StringVar(&o.credentialEnv, "credential-env", o.credentialEnv, "the environment variable holding the CI credential")
	f.IntVar(&o.wait, "wait", o.wait, "seconds to wait for records still on their way (-1: the org policy's wait)")
	f.StringArrayVar(&o.drivers, "driver", nil, "download a pinned CI driver: kind/name=sha256 (repeatable)")
	f.StringVar(&o.driverDir, "driver-dir", "", "the directory pinned drivers are written to")
	f.StringVar(&o.driverOS, "driver-os", o.driverOS, "the driver platform's OS")
	f.StringVar(&o.driverArch, "driver-arch", o.driverArch, "the driver platform's architecture")
	return cmd
}

func runSecurityVerifyFetch(ctx context.Context, stdout, stderr io.Writer, o securityVerifyFetchOpts) error {
	if ctx == nil {
		ctx = context.Background()
	}
	fail := func(format string, args ...any) error {
		fmt.Fprintf(stderr, "observer security verify fetch: UNKNOWN: "+format+"\n", args...)
		return exitErr(secverify.ExitUnknown)
	}
	switch {
	case o.orgURL == "" || o.policyOut == "":
		return fail("--org-url and --policy-out are required")
	case o.lookupOut != "" && o.commits == "":
		return fail("--lookup-out needs --commits")
	case len(o.drivers) > 0 && o.driverDir == "":
		return fail("--driver needs --driver-dir")
	case o.wait > verifyOrgMaxWait:
		return fail("--wait is at most %d seconds", verifyOrgMaxWait)
	}
	for _, a := range [][2]string{{"--commits", o.commits}, {"--policy-out", o.policyOut}, {"--lookup-out", o.lookupOut}, {"--driver-dir", o.driverDir}} {
		if why := secverify.PathArgRefusal(a[0], a[1], runtime.GOOS == "windows"); why != "" {
			return fail("%s", why)
		}
	}
	client, err := seccifetch.New(o.orgURL, os.Getenv(o.credentialEnv))
	if err != nil {
		// no-bare-usd:allow: not money, $%%s names the environment variable.
		return fail("%v (the credential is read from $%s)", err, o.credentialEnv)
	}
	policy, err := client.Policy(ctx)
	if err != nil {
		return fail("CI policy: %v", err)
	}
	if err := writeFileAtomic(o.policyOut, policy); err != nil {
		return fail("write the policy: %v", err)
	}
	fmt.Fprintln(stdout, "CI policy fetched (verify checks its signature)")
	for _, d := range o.drivers {
		if err := fetchVerifyDriver(ctx, client, d, o); err != nil {
			return fail("driver %s: %v", clipVerifyArg(d), err)
		}
		fmt.Fprintf(stdout, "driver %s fetched and matched its pin\n", clipVerifyArg(d))
	}
	if o.lookupOut == "" {
		return nil
	}
	b, err := os.ReadFile(o.commits)
	if err != nil {
		return fail("read the commits: %v", err)
	}
	var req orgcontract.CILookupRequest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return fail("the commits file is not a lookup request: %v", err)
	}
	// Remove a stale answer first: an answer from an earlier run must never
	// stand in for this one.
	if err := os.Remove(o.lookupOut); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fail("remove the old lookup answer: %v", err)
	}
	if len(req.Commits) == 0 {
		fmt.Fprintln(stdout, "no commits to look up")
		return nil
	}
	wait := o.wait
	if wait < 0 {
		wait = seccifetch.PolicyWait(policy)
	}
	if wait < 0 || wait > verifyOrgMaxWait {
		wait = 180
	}
	res := client.LookupWait(ctx, req, time.Duration(wait)*time.Second)
	if res.Doc == nil {
		fmt.Fprintf(stderr, "observer security verify fetch: WARNING: the org gave no lookup answer in %ds (%v); every commit without a note reads as unknown_provenance\n", wait, res.LastErr)
		return nil
	}
	if err := writeFileAtomic(o.lookupOut, res.Doc); err != nil {
		return fail("write the lookup answer: %v", err)
	}
	state := "settled"
	if !res.Settled {
		state = fmt.Sprintf("not settled after %ds: commits still without a final record read as unknown_provenance", wait)
	}
	fmt.Fprintf(stdout, "change record lookup answered after %d attempt(s), %s\n", res.Attempts, state)
	return nil
}

// fetchVerifyDriver downloads one pinned driver into the driver directory.
func fetchVerifyDriver(ctx context.Context, client *seccifetch.Client, spec string, o securityVerifyFetchOpts) error {
	m := verifyDriverRE.FindStringSubmatch(spec)
	if m == nil {
		return errors.New("want kind/name=sha256")
	}
	if err := os.MkdirAll(o.driverDir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(o.driverDir, ".driver-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, derr := client.Driver(ctx, m[1], m[2], o.driverOS, o.driverArch, m[3], tmp)
	cerr := tmp.Close()
	if derr == nil {
		derr = cerr
	}
	if derr != nil {
		_ = os.Remove(name)
		return derr
	}
	if err := os.Rename(name, filepath.Join(o.driverDir, m[2])); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

// clipVerifyArg bounds an argument echoed into the log.
func clipVerifyArg(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
