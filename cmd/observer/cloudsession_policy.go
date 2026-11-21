package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudsession"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// cloudsession_policy.go is `observer cloud-session init --guard`'s fetch
// (lane CA-C2, decision CA-D9): it gets the signed policy material from the
// destination, verifies it against the pinned distribution key, and returns
// the policy file the planner commits. It runs on the developer's machine at
// init time, never in the sandbox:
//
//   - org: the org's guard policy bundle and the member's budget document,
//     through this node's enrolled org client (the existing `org.client`
//     egress lane; every fetch goes through its key-pinned acceptance gate),
//     then re-verified here against the key this node pinned at enrolment.
//   - node: the owner's own node signs its user guard policy with its own
//     cloud-session policy key (generated once, 0600 beside the database).

// sandboxPolicyResult is a fetched, verified policy file.
type sandboxPolicyResult struct {
	Policy []byte
	KeyPin string
	// Notes are honest one-liners init prints (no budget, why).
	Notes []string
}

// cloudSessionPolicyKeyFile is the node's policy signing key, base64 of the
// Ed25519 seed, in the cloud-session state directory.
const cloudSessionPolicyKeyFile = "policy-signing-key"

// fetchOrgSandboxPolicy is the org fetch; a variable so tests can stand in
// for an org server.
var fetchOrgSandboxPolicy = defaultFetchOrgSandboxPolicy

// fetchSandboxPolicy fetches the policy for a destination.
func fetchSandboxPolicy(ctx context.Context, dest cloudsession.DestinationKind, configPath string, now time.Time) (sandboxPolicyResult, error) {
	switch dest {
	case cloudsession.DestOrg:
		return fetchOrgSandboxPolicy(ctx, configPath, now)
	case cloudsession.DestNode:
		cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
		if err != nil {
			return sandboxPolicyResult{}, fmt.Errorf("load config: %w", err)
		}
		home, _ := os.UserHomeDir()
		return nodeSandboxPolicy(cfg, home, now)
	}
	return sandboxPolicyResult{}, fmt.Errorf("--guard fetches its policy from the org or node destination, not %q", dest)
}

func defaultFetchOrgSandboxPolicy(ctx context.Context, configPath string, now time.Time) (sandboxPolicyResult, error) {
	b, err := buildOrgBundle(ctx, configPath)
	if err != nil {
		return sandboxPolicyResult{}, err
	}
	defer b.cleanup()
	enr, err := b.store.LoadEnrolment(ctx)
	if err != nil {
		return sandboxPolicyResult{}, fmt.Errorf("load enrolment: %w", err)
	}
	if enr == nil {
		return sandboxPolicyResult{}, errors.New("--guard --destination org verifies the org's policy against the key this node pinned at enrolment; enrol first (observer org enroll), or use --destination node")
	}
	cache := orgBundleCachePath(b.cfg)
	if cache == "" {
		return sandboxPolicyResult{}, errors.New("[guard.rules].org_bundle is empty: there is no verified org bundle location to fetch into")
	}
	res, err := b.client.FetchPolicyBundle(ctx, cache)
	if err != nil {
		return sandboxPolicyResult{}, fmt.Errorf("fetch the org guard policy: %w", err)
	}
	switch res.Status {
	case orgclient.PolicyApplied, orgclient.PolicyUnchanged:
	case orgclient.PolicyNone:
		return sandboxPolicyResult{}, errors.New("the org publishes no guard policy bundle; publish one on the org dashboard, or use --destination node")
	default:
		return sandboxPolicyResult{}, fmt.Errorf("the org guard policy was refused (%s): %s", res.Status, res.Detail)
	}
	raw, err := os.ReadFile(cache)
	if err != nil {
		return sandboxPolicyResult{}, fmt.Errorf("read the verified org bundle: %w", err)
	}
	var bundle orgcontract.PolicyBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return sandboxPolicyResult{}, fmt.Errorf("decode the verified org bundle: %w", err)
	}
	pin, ok, err := b.store.LoadOrgPolicyKeyPin(ctx, orgclient.PolicyKeyPinPath(enr.OrgServerURL))
	if err != nil {
		return sandboxPolicyResult{}, err
	}
	if !ok {
		return sandboxPolicyResult{}, errors.New("this node has not pinned the org's policy key; re-enrol")
	}
	// The composed v3 bundle's project deliveries are not covered by its own
	// signature (the node strips them before caching anyway); everything
	// else is re-verified offline in the sandbox, binding included.
	bundle.Projects = nil
	policy := cloudsession.SandboxPolicy{
		Origin: cloudsession.OriginOrg, KeyPin: pin, FetchedAt: now.UTC().Format(time.RFC3339), Guard: bundle,
	}
	var notes []string
	if budget, note := orgSandboxBudget(ctx, b, enr.OrgID, enr.UserID, bundle); budget != nil {
		policy.Budget = budget
	} else if note != "" {
		notes = append(notes, note)
	}
	return encodeVerifiedPolicy(policy, pin, notes)
}

// orgSandboxBudget fetches the member's signed budget document and keeps it
// only when it verifies under the same pinned key as the guard bundle. A
// missing or unverifiable document is a note, never an error: the guard
// still ships, without the soft budget stop.
func orgSandboxBudget(ctx context.Context, b orgBundle, orgID, subject string, bundle orgcontract.PolicyBundle) (*cloudsession.SandboxBudget, string) {
	out, err := b.client.FetchBudgetPolicy(ctx)
	if err != nil && !out.HaveBody {
		return nil, "no soft budget stop: the org budget document could not be fetched (" + err.Error() + ")"
	}
	if !out.HaveBody || out.Body.Empty() {
		return nil, "no soft budget stop: the org sets no budget for you"
	}
	cached, err := b.store.LoadOrgBudget(ctx)
	if err != nil || !cached.Have {
		return nil, "no soft budget stop: the verified budget document is not stored"
	}
	pub, err := orgcontract.VerifyPolicyBundle(bundle)
	if err != nil {
		return nil, ""
	}
	if err := orgcontract.VerifyBudgetPolicy(pub, orgID, subject, cached.Document); err != nil {
		return nil, "no soft budget stop: the budget document is signed by a different org key than the guard policy"
	}
	return &cloudsession.SandboxBudget{OrgID: orgID, Subject: subject, Document: cached.Document}, ""
}

// nodeSandboxPolicy signs this node's user guard policy with the node's own
// cloud-session policy key.
func nodeSandboxPolicy(cfg config.Config, home string, now time.Time) (sandboxPolicyResult, error) {
	priv, err := loadOrCreateCloudSessionPolicyKey(filepath.Join(filepath.Dir(cfg.Observer.DBPath), "cloud-session"))
	if err != nil {
		return sandboxPolicyResult{}, err
	}
	var notes []string
	toml := "# SuperBased Observer cloud-session policy: no user guard policy on the signing node; the built-in rules apply.\n"
	if p := guard.UserPolicyPath(cfg.Guard, home); p != "" {
		switch raw, err := os.ReadFile(p); {
		case err == nil:
			toml = string(raw)
		case errors.Is(err, os.ErrNotExist):
			notes = append(notes, "the node has no user guard policy ("+p+"); the sandbox runs the built-in rules")
		default:
			return sandboxPolicyResult{}, fmt.Errorf("read the user guard policy: %w", err)
		}
	}
	notes = append(notes, "the node policy carries your user guard policy file only; [guard] config tuning and any org floor are not carried")
	version := now.Unix()
	pub := priv.Public().(ed25519.PublicKey)
	pin := orgcontract.PublicKeyPinHash(pub)
	policy := cloudsession.SandboxPolicy{
		Origin: cloudsession.OriginNode, KeyPin: pin, FetchedAt: now.UTC().Format(time.RFC3339),
		Guard: orgcontract.PolicyBundle{
			Version: version, BundleTOML: toml,
			Signature: orgcontract.SignPolicyBundle(priv, version, []byte(toml)),
			PublicKey: base64.RawURLEncoding.EncodeToString(pub), SignedAt: now.UTC().Format(time.RFC3339),
			Description: "observer cloud-session node policy",
		},
	}
	return encodeVerifiedPolicy(policy, pin, notes)
}

// encodeVerifiedPolicy encodes the file and verifies it end to end, the
// same check the sandbox gate runs.
func encodeVerifiedPolicy(p cloudsession.SandboxPolicy, pin string, notes []string) (sandboxPolicyResult, error) {
	raw, err := cloudsession.EncodePolicy(p)
	if err != nil {
		return sandboxPolicyResult{}, err
	}
	if _, err := cloudsession.VerifyPolicy(raw, true, cloudsession.PolicyPin{KeyPin: pin, Digest: cloudsession.PolicyDigest(raw)}); err != nil {
		return sandboxPolicyResult{}, fmt.Errorf("the fetched policy does not verify against the pinned key: %w", err)
	}
	return sandboxPolicyResult{Policy: raw, KeyPin: pin, Notes: notes}, nil
}

// loadOrCreateCloudSessionPolicyKey returns the node's policy signing key,
// creating it (0600, in a 0700 directory) on first use.
func loadOrCreateCloudSessionPolicyKey(dir string) (ed25519.PrivateKey, error) {
	path := filepath.Join(dir, cloudSessionPolicyKeyFile)
	if b, err := os.ReadFile(path); err == nil {
		seed, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if derr != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("%s is not a policy signing key; move it aside to mint a new one (every committed --guard setup must then re-run init)", path)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read the policy signing key: %w", err)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("mint the policy signing key: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("write the policy signing key: %w", err)
	}
	_, werr := f.WriteString(base64.StdEncoding.EncodeToString(seed) + "\n")
	cerr := f.Close()
	if werr != nil || cerr != nil {
		return nil, fmt.Errorf("write the policy signing key: %w", errors.Join(werr, cerr))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
