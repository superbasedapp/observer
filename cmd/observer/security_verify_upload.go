//go:build !sbo_omit_security

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/spf13/pflag"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/seccifetch"
	"github.com/marmutapp/superbased-observer/internal/secverify"
)

// security_verify_upload.go is `observer security verify --upload` (lane
// GATES-SEC, org.security.githubapp): the verify workflow's separate result
// job posts the verdict job's SARIF artifact to the org under the CI
// credential. It runs no check of its own: a missing or foreign SARIF
// uploads unknown. The repository, the run attempt and the run's page come
// from the runner (GITHUB_REPOSITORY, GITHUB_RUN_ATTEMPT, GITHUB_SERVER_URL
// and GITHUB_RUN_ID) unless a flag names them; the org binds the result to
// the job's GitHub Actions OIDC token (audit finding F1), which it reads
// from the runner (the job needs `permissions: id-token: write`), and takes
// the attempt and the run's page from that token, never from these values.
// --upload-pending registers the run as pending at its start (audit finding
// F2): a commit whose verdict never arrives reads error once the org's
// bounded wait passes.

// verifyUploadIDTokenClient is the runner OIDC request's client (nil: the
// default; tests replace it).
var verifyUploadIDTokenClient *http.Client

// verifyUploadOpts are the upload mode's flags.
type verifyUploadOpts struct {
	sarif, orgURL, credentialEnv string
	repository, runURL           string
	attempt                      int
	// audience is the OIDC token's audience (empty: --org-url without a
	// trailing slash).
	audience string
	// pending uploads a pending registration (no SARIF read).
	pending bool
}

// active reports whether the upload mode was asked for.
func (o verifyUploadOpts) active() bool { return o.sarif != "" || o.pending }

// verifyUploadSARIFCap caps the artifact read.
const verifyUploadSARIFCap = 64 << 20

func addVerifyUploadFlags(f *pflag.FlagSet, o *verifyUploadOpts) {
	f.StringVar(&o.sarif, "upload", "", "upload mode: post the verdict job's SARIF (this file; absent uploads unknown) to the org with --org-url, under the CI credential")
	f.StringVar(&o.orgURL, "org-url", "", "upload mode: the org server's https base URL")
	f.StringVar(&o.credentialEnv, "upload-credential-env", verifyOrgCredentialEnv, "upload mode: the environment variable holding the CI credential")
	f.StringVar(&o.repository, "repository", "", "upload mode: owner/name of the repository under test (default $GITHUB_REPOSITORY)")
	f.StringVar(&o.runURL, "run-url", "", "upload mode: the run's page on github.com (default from $GITHUB_SERVER_URL, $GITHUB_REPOSITORY and $GITHUB_RUN_ID)")
	f.IntVar(&o.attempt, "run-attempt", 0, "upload mode: the run attempt (default $GITHUB_RUN_ATTEMPT; the org takes the attempt from the job's OIDC token)")
	f.StringVar(&o.audience, "oidc-audience", "", "upload mode: the audience of the job's GitHub Actions OIDC token (default --org-url; must equal the org's [security.githubapp].oidc_audience or [server].external_url)")
	f.BoolVar(&o.pending, "upload-pending", false, "upload mode: register this run as pending (no SARIF read), so the org's status reads pending, then error if no verdict arrives in time")
}

// verifyUploadInput fills the runner's values a flag left empty.
func verifyUploadInput(o securityVerifyOpts, getenv func(string) string) (secverify.ResultUploadInput, error) {
	u := o.upload
	in := secverify.ResultUploadInput{Repository: u.repository, Base: o.base, Head: o.head, Attempt: u.attempt, RunURL: u.runURL}
	if in.Repository == "" {
		in.Repository = getenv("GITHUB_REPOSITORY")
	}
	if in.Attempt == 0 {
		n, err := strconv.Atoi(strings.TrimSpace(getenv("GITHUB_RUN_ATTEMPT")))
		if err != nil {
			return in, errors.New("no --run-attempt and no $GITHUB_RUN_ATTEMPT")
		}
		in.Attempt = n
	}
	if in.RunURL == "" {
		server, id := strings.TrimRight(getenv("GITHUB_SERVER_URL"), "/"), getenv("GITHUB_RUN_ID")
		if server == "" || id == "" {
			return in, errors.New("no --run-url and no $GITHUB_SERVER_URL and $GITHUB_RUN_ID")
		}
		in.RunURL = server + "/" + in.Repository + "/actions/runs/" + id + "/attempts/" + strconv.Itoa(in.Attempt)
	}
	return in, nil
}

// runSecurityVerifyUpload posts one result. Exit 0 when the org stored it,
// else the unknown code (the workflow treats the job's failure as a
// warning).
func runSecurityVerifyUpload(ctx context.Context, stdout, stderr io.Writer, o securityVerifyOpts) error {
	if ctx == nil {
		ctx = context.Background()
	}
	fail := func(format string, args ...any) error {
		fmt.Fprintf(stderr, "observer security verify --upload: NOT UPLOADED: "+format+"\n", args...)
		return exitErr(secverify.ExitUnknown)
	}
	switch {
	case o.upload.orgURL == "":
		return fail("--org-url is required")
	case o.policyFile != "" || o.baseFile != "" || o.orgPolicy != "" || o.sarif != "" || o.keys != "" || o.installIndex != "":
		return fail("--upload runs no check: it takes only --org-url, --base, --head and the run flags")
	case !verifyRevRE.MatchString(o.head) || (o.base != "" && !verifyRevRE.MatchString(o.base)):
		return fail("--head (and --base) must be full hex commit ids")
	}
	if o.upload.pending && o.upload.sarif != "" {
		return fail("--upload-pending reads no SARIF: drop --upload")
	}
	if !o.upload.pending {
		if why := secverify.PathArgRefusal("--upload", o.upload.sarif, runtime.GOOS == "windows"); why != "" {
			return fail("%s", why)
		}
	}
	in, err := verifyUploadInput(o, os.Getenv)
	if err != nil {
		return fail("%v", err)
	}
	var u orgcontract.CIResultUpload
	if o.upload.pending {
		u, err = secverify.PendingResult(in)
	} else {
		var sarif []byte
		sarif, err = readVerifyUploadSARIF(o.upload.sarif)
		if err != nil {
			return fail("read the SARIF: %v", err)
		}
		u, err = secverify.ResultFromSARIF(sarif, in)
	}
	if err != nil {
		return fail("%v (repository %q, attempt %d)", err, clipVerifyArg(in.Repository), in.Attempt)
	}
	client, err := seccifetch.New(o.upload.orgURL, os.Getenv(o.upload.credentialEnv))
	if err != nil {
		// no-bare-usd:allow: not money, $%%s names the environment variable.
		return fail("%v (the credential is read from $%s)", err, o.upload.credentialEnv)
	}
	aud := strings.TrimSpace(o.upload.audience)
	if aud == "" {
		aud = strings.TrimRight(strings.TrimSpace(o.upload.orgURL), "/")
	}
	tok, err := seccifetch.ActionsIDToken(ctx, verifyUploadIDTokenClient, os.Getenv(seccifetch.EnvIDTokenRequestURL), os.Getenv(seccifetch.EnvIDTokenRequestToken), aud)
	if err != nil {
		return fail("%v", err)
	}
	a, err := client.UploadResult(ctx, u, tok)
	if err != nil {
		return fail("%v", err)
	}
	stored := "stored"
	if !a.Stored {
		stored = "already on record"
	}
	fmt.Fprintf(stdout, "verdict %s for %s@%s attempt %d uploaded (%s)\n", u.Verdict, u.Repository, u.HeadSHA[:12], u.Attempt, stored)
	return nil
}

// readVerifyUploadSARIF reads the artifact, capped; nil when it is absent
// (the verdict job wrote none, which uploads unknown).
func readVerifyUploadSARIF(path string) ([]byte, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, verifyUploadSARIFCap+1))
	if err != nil {
		return nil, err
	}
	if len(b) > verifyUploadSARIFCap {
		return []byte("{}"), nil
	}
	return b, nil
}
