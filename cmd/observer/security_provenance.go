//go:build !sbo_omit_security

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
	"github.com/marmutapp/superbased-observer/internal/commitscan"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/machineid"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
	"github.com/marmutapp/superbased-observer/internal/secchange"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_provenance.go is the node side of the signed AI change record
// per commit (security pillar plan 7.10, Q8; component
// security.provenance; lane SEC-F2A): the signing key in the OS keychain
// (internal/keystore; its 0600 file fallback reported as file_key), the
// record builder bound into the commit scanner's per-commit seam
// (commitscan.Options.OnCommit), and the producer behind the org wire's
// SecurityOrgProviders.ChangeRecords.
//
// Opt-in: security.provenance is off in every distro (Q9) and listed in
// securityOptIn, so an install with no [components] block never generates
// a key, records nothing, pushes no change record row and writes no
// repository. The pure protocol is internal/secchange; the table owner is
// internal/store/secchange.go.

// securityProvenanceComponent is the catalog id.
const securityProvenanceComponent = "security.provenance"

// provenanceKeystoreService is the keychain service the signing keys live
// under; each key is one secret named provenanceKeyName(id).
const provenanceKeystoreService = "sbo-change-record-v1"

// provenanceGitTimeout bounds one read-only git call of the builder.
const provenanceGitTimeout = 20 * time.Second

func provenanceKeyName(id string) string { return "change-key-" + id }

// provenanceSelected is the component's one switch (security_optin.go).
func provenanceSelected(snap componentstate.Snapshot) bool {
	return securitySelected(snap, securityProvenanceComponent)
}

// provenanceRT is the running service while the daemon's provenance loop
// runs; nil otherwise, so the commit seam and the org wire do nothing.
var provenanceRT atomic.Pointer[provenanceSvc]

// provenanceGit is the read-only git call the builder uses (a var so tests
// can run against a throwaway repository with the real envelope).
type provenanceGit func(ctx context.Context, root string, maxBytes int, timeout time.Duration, args ...string) ([]byte, bool, error)

// provenanceSvc builds, signs and stores change records.
type provenanceSvc struct {
	st *store.Store
	// openKeys selects the backend new keys are stored in, with the named
	// reason when it is not the OS keychain (keystore.OpenReport).
	openKeys func() (keystore.Store, string)
	// storeFor is the store that holds a key of a storage class (the OS
	// keychain for keychain, the 0600 file fallback for file_key), so a key
	// is always read from where it was stored, whatever this process's probe
	// selected (the macOS live run, check 6: a daemon in a locked
	// non-interactive session and a CLI in an unlocked one must never read
	// each other's key from the wrong backend and regenerate it). nil, or a
	// nil result, reads the backend openKeys selected.
	storeFor func(storage string) keystore.Store
	// enrolment reads the node's org enrolment (store.LoadEnrolment).
	enrolment func(ctx context.Context) (*store.Enrolment, error)
	// keyDir is the 0600 file fallback directory ("" in tests): it also
	// holds the named reason a key is in the file fallback.
	keyDir     string
	git        provenanceGit
	now        func() time.Time
	logger     *slog.Logger
	linkWindow time.Duration
	// bundlePath is the cached org guard bundle (orgBundleCachePath): the
	// record's org project id and policy version come from it and the
	// project audience's match record (provenanceOrgProject). "" on a node
	// that holds none.
	bundlePath string
	// enrol is the managed node's key enrolment (security_provenance_enrol.go);
	// nil never calls the org. nextEnrol spaces attempts after a failure.
	enrol     provenanceEnroller
	nextEnrol time.Time

	mu         sync.Mutex
	keys       keystore.Store
	keysReason string
}

// newProvenanceSvc wires the service over st, with the keychain opened
// lazily under fallbackDir.
func newProvenanceSvc(st *store.Store, fallbackDir string, linkWindow time.Duration, logger *slog.Logger) *provenanceSvc {
	if logger == nil {
		logger = slog.Default()
	}
	return &provenanceSvc{
		st: st,
		openKeys: func() (keystore.Store, string) {
			o := keystore.OpenReport(provenanceKeystoreService, fallbackDir, logger)
			return o.Store, o.Reason
		},
		storeFor:   provenanceStoreFor(fallbackDir),
		enrolment:  st.LoadEnrolment,
		keyDir:     fallbackDir,
		git:        gitview.RunReadOnlyTimeout,
		now:        time.Now,
		logger:     logger,
		linkWindow: linkWindow,
	}
}

// provenanceStoreFor maps a key's storage class onto the store that holds
// it, with no probe: the keychain for keychain, the 0600 file fallback for
// file_key (where this build verifies it).
func provenanceStoreFor(fallbackDir string) func(string) keystore.Store {
	return func(storage string) keystore.Store {
		switch storage {
		case secchange.StorageKeychain:
			return keystore.NewKeychainStore(provenanceKeystoreService)
		case secchange.StorageFileKey:
			if keystore.FileFallbackSecure() {
				return keystore.NewFileStore(provenanceKeystoreService, fallbackDir)
			}
		}
		return nil
	}
}

// provenanceStorageReasonFile names, beside the 0600 key files, why the
// active key is in the file fallback (a reason code, not a secret).
const provenanceStorageReasonFile = "keychain-fallback-reason"

// provenanceStorageReason reads the named reason the active file_key key
// was stored in the fallback ("" when none was recorded).
func provenanceStorageReason(keyDir string) string {
	if keyDir == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(keyDir, provenanceStorageReasonFile)) //nolint:gosec // G304: Observer's own key directory.
	if err != nil || len(b) > 64 {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// provenanceKeyDir is the keystore's 0600 file fallback directory, beside
// the database (the delivery credential precedent).
func provenanceKeyDir(cfg config.Config) string {
	return filepath.Join(filepath.Dir(cfg.Observer.DBPath), "provenance-key")
}

func (p *provenanceSvc) keystore() (keystore.Store, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.keys == nil {
		p.keys, p.keysReason = p.openKeys()
	}
	return p.keys, p.keysReason
}

// seedStore is the store holding a key of storage class storage.
func (p *provenanceSvc) seedStore(storage string) keystore.Store {
	if p.storeFor != nil {
		if s := p.storeFor(storage); s != nil {
			return s
		}
	}
	ks, _ := p.keystore()
	return ks
}

// keyStorage maps the keystore backend onto the record's storage class; ""
// when the backend cannot hold a key (fail closed: no record is signed).
func keyStorage(backend string) string {
	switch backend {
	case "keychain":
		return secchange.StorageKeychain
	case "file", "memory":
		return secchange.StorageFileKey
	}
	return ""
}

// provenanceEnrolment is the enrolment a key is bound to: the org and the
// enrolment time ("" on a node that is not enrolled), and the managed
// machine identity. A read that fails is an error, never "not enrolled"
// (audit finding F5: one busy read would otherwise rotate the key as a
// re-enrolment).
func (p *provenanceSvc) provenanceEnrolment(ctx context.Context) (enrolment, orgID, machine string, err error) {
	load := p.enrolment
	if load == nil {
		load = p.st.LoadEnrolment
	}
	enr, err := load(ctx)
	if err != nil {
		return "", "", "", fmt.Errorf("read the org enrolment: %w", err)
	}
	if enr == nil {
		return "", "", "", nil
	}
	enrolment, orgID = enr.OrgID+"|"+enr.EnrolledAt, enr.OrgID
	// A managed node names its machine: a managed enrolment, or one whose
	// org switched it to enterprise (P-205), which the org server certifies
	// as managed too. A grant read error names none (the key stays
	// self-certified until the next attempt).
	if managed, merr := orgclient.NodeManagedFor(ctx, p.st, enr); merr == nil && managed {
		if mid, err := machineid.ForOrg(enr.OrgID); err == nil {
			machine = mid
		}
	}
	return enrolment, orgID, machine, nil
}

// signingKey returns the key to sign with, generating or rotating it per
// secchange.RotationDue (90 days, a re-enrolment, a retired or missing
// key). A rotated key is retired (its public half stays) and its private
// seed is deleted (retireKey).
func (p *provenanceSvc) signingKey(ctx context.Context) (ed25519.PrivateKey, store.ChangeKey, error) {
	ks, reason := p.keystore()
	storage := keyStorage(ks.Backend())
	if storage == "" {
		return nil, store.ChangeKey{}, fmt.Errorf("no protected key storage on this machine (%s): %s", keystore.FallbackDetail(reason), ks.SecurityDiagnostic())
	}
	enrolment, _, _, err := p.provenanceEnrolment(ctx)
	if err != nil {
		return nil, store.ChangeKey{}, err
	}
	now := p.now().UTC()
	k, ok, err := p.st.ActiveChangeKey(ctx)
	if err != nil {
		return nil, k, err
	}
	state := secchange.KeyState{Exists: ok, Enrolment: k.Enrolment, CurrentEnrolment: enrolment}
	if ok {
		state.CreatedAt, _ = time.Parse(time.RFC3339, k.CreatedAt)
	}
	switch rot := secchange.RotationDue(state, now); rot {
	case secchange.RotationKeep:
		seed, gerr := p.seedStore(k.Storage).Get(provenanceKeyName(k.KeyID))
		if gerr != nil && !errors.Is(gerr, keystore.ErrNotFound) {
			// The key's own store answered with an error, not "absent" (a
			// locked macOS keychain in a non-interactive session answers
			// errSecInteractionNotAllowed): the key is kept, never replaced,
			// and no record is signed until it can be read.
			why := "its store answered with an error"
			if k.Storage == secchange.StorageKeychain {
				why = keystore.FallbackDetail(keystore.FallbackReason(gerr))
			}
			return nil, k, fmt.Errorf("the signing key %s (%s) is not readable now: %s; it is kept, and no record is signed until it can be read: %w", k.KeyID, k.Storage, why, gerr)
		}
		raw, derr := base64.StdEncoding.DecodeString(seed)
		if gerr == nil && derr == nil && len(raw) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(raw), k, nil
		}
		// The secret is gone from its store (wiped, another user): the key
		// can sign nothing more, so it is retired and replaced.
		if err := p.retireKey(ctx, k, "key_missing", now); err != nil {
			return nil, k, err
		}
	default:
		if ok {
			if err := p.retireKey(ctx, k, string(rot), now); err != nil {
				return nil, k, err
			}
		}
	}
	return p.generateKey(ctx, ks, storage, reason, enrolment, now)
}

// provenanceRotatedByHand is the retire reason of `rotate-key` (the
// dashboard's Rotate key): a person rotated a key they may suspect, so the
// keys file export revokes it (provenanceKeysFile).
const provenanceRotatedByHand = "rotated_by_hand"

// retireKey retires a key and deletes its private seed from the store that
// holds it and from the backend this process selected (audit finding F1):
// a retired key can sign nothing more, here or anywhere its seed was. The
// keys file export bounds it with not_after = retired_at, and revokes a key
// rotated by hand.
func (p *provenanceSvc) retireKey(ctx context.Context, k store.ChangeKey, reason string, at time.Time) error {
	if err := p.st.RetireChangeKey(ctx, k.KeyID, reason, at); err != nil {
		return err
	}
	p.dropSeed(k.KeyID, k.Storage)
	return nil
}

// dropSeed deletes a key's private seed from its store and the selected
// backend. Best-effort: a failure is logged, and retried by the sweep at
// the next key generation (sweepRetiredSeeds). Absence is not an error.
func (p *provenanceSvc) dropSeed(id, storage string) {
	name := provenanceKeyName(id)
	held := p.seedStore(storage)
	ks, _ := p.keystore()
	for i, s := range []keystore.Store{held, ks} {
		if s == nil || (i > 0 && held != nil && s.Backend() == held.Backend()) {
			continue
		}
		if err := s.Delete(name); err != nil {
			p.logger.Warn("security provenance: a retired key's secret was not deleted; it is retried at the next key change",
				"key_id", id, "backend", s.Backend(), "err", err)
		}
	}
}

// sweepRetiredSeeds deletes the seed of every retired key again, so a
// deletion that failed once (a locked keychain) is not left behind.
func (p *provenanceSvc) sweepRetiredSeeds(ctx context.Context) {
	keys, err := p.st.ChangeKeys(ctx)
	if err != nil {
		return
	}
	for _, k := range keys {
		if k.RetiredAt != "" {
			p.dropSeed(k.KeyID, k.Storage)
		}
	}
}

// recordStorageReason keeps the named reason a file_key key is in the file
// fallback, for status and doctor; any other storage clears it.
func (p *provenanceSvc) recordStorageReason(storage, reason string) {
	if p.keyDir == "" {
		return
	}
	path := filepath.Join(p.keyDir, provenanceStorageReasonFile)
	if storage != secchange.StorageFileKey || reason == "" {
		_ = os.Remove(path)
		return
	}
	if os.MkdirAll(p.keyDir, 0o700) == nil {
		_ = os.WriteFile(path, []byte(reason+"\n"), 0o600)
	}
}

func (p *provenanceSvc) generateKey(ctx context.Context, ks keystore.Store, storage, reason, enrolment string, now time.Time) (ed25519.PrivateKey, store.ChangeKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, store.ChangeKey{}, err
	}
	id := secchange.KeyID(pub)
	if err := ks.Set(provenanceKeyName(id), base64.StdEncoding.EncodeToString(priv.Seed())); err != nil {
		return nil, store.ChangeKey{}, fmt.Errorf("store the signing key: %w", err)
	}
	k := store.ChangeKey{
		KeyID: id, PublicKey: base64.StdEncoding.EncodeToString(pub), Storage: storage,
		Attestation: secchange.AttestationSelf, Enrolment: enrolment, CreatedAt: now.Format(time.RFC3339),
	}
	if err := p.st.SaveChangeKey(ctx, k); err != nil {
		return nil, k, err
	}
	p.recordStorageReason(storage, reason)
	p.sweepRetiredSeeds(ctx)
	if reason != "" {
		p.logger.Warn("security provenance: signing key stored in the 0600 file fallback", "key_id", id, "reason", reason, "detail", keystore.FallbackDetail(reason))
	}
	p.logger.Info("security provenance: signing key generated", "key_id", id, "storage", storage)
	return priv, k, nil
}

// rotateKey retires the active key by hand (`observer security provenance
// rotate-key`, the dashboard's Rotate key): its seed is deleted, and the
// keys file export revokes it. The next record generates a new key.
func (p *provenanceSvc) rotateKey(ctx context.Context) (string, error) {
	k, ok, err := p.st.ActiveChangeKey(ctx)
	if err != nil || !ok {
		return "", err
	}
	return k.KeyID, p.retireKey(ctx, k, provenanceRotatedByHand, p.now())
}

// firstKeyAt is when the node's first key was made: commits from before
// it get no record (provenance never signs history it did not see).
func (p *provenanceSvc) firstKeyAt(ctx context.Context) (time.Time, error) {
	keys, err := p.st.ChangeKeys(ctx)
	if err != nil {
		return time.Time{}, err
	}
	var first time.Time
	for _, k := range keys {
		if t, err := time.Parse(time.RFC3339, k.CreatedAt); err == nil && (first.IsZero() || t.Before(first)) {
			first = t
		}
	}
	return first, nil
}

// provenanceCommitGrace lets a commit made just before the first key (the
// commit that turned the component on, a clock skew) still get a record.
const provenanceCommitGrace = time.Hour

// provenanceOutcome is what recordCommit did, for the logs and the tests.
type provenanceOutcome string

const (
	provRecorded  provenanceOutcome = "recorded"
	provExists    provenanceOutcome = "already_recorded"
	provBeforeKey provenanceOutcome = "before_provenance"
	provNoAI      provenanceOutcome = "no_ai_attribution"
	provNotLedger provenanceOutcome = "not_in_ledger"
)

// recordCommit builds, signs and stores the record of one commit the
// scanner read, when the attribution ties AI sessions to it.
func (p *provenanceSvc) recordCommit(ctx context.Context, root commitscan.Root, c commitlog.Commit) (provenanceOutcome, error) {
	rootHash := secposture.ProjectRootHash(root.RootPath)
	if has, err := p.st.HasChangeRecord(ctx, rootHash, c.SHA); err != nil || has {
		return provExists, err
	}
	if first, err := p.firstKeyAt(ctx); err != nil {
		return "", err
	} else if first.IsZero() || c.CommittedAt.Before(first.Add(-provenanceCommitGrace)) {
		// No key yet (the loop makes one when it starts), or a commit from
		// before provenance was on: no record.
		return provBeforeKey, nil
	}
	facts, skip, err := p.loadFacts(ctx, root, rootHash, c)
	switch {
	case err != nil:
		return "", err
	case skip == store.ChangeSkipUnknownCommit:
		return provNotLedger, nil
	case skip != "":
		return provNoAI, nil
	}
	priv, key, err := p.signingKey(ctx)
	if err != nil {
		return "", err
	}
	tree, fp, fpState, err := p.commitIdentity(ctx, root.RootPath, c.SHA, facts)
	if err != nil {
		return "", err
	}
	_, orgID, machine, err := p.provenanceEnrolment(ctx)
	if err != nil {
		return "", err
	}
	orgProject, policyVersion := provenanceOrgProject(p.bundlePath, root.RootPath)
	rec := secchange.Build(provenanceBuildInput(facts, secchange.Binding{
		CommitSHA: c.SHA, TreeSHA: tree, PatchFP: fp, PatchFPState: fpState,
		OrgID: orgID, MachineIdentity: machine, ProjectHash: rootHash,
		OrgProjectID: orgProject, PolicyVersion: policyVersion,
	}, secchange.KeyRef{ID: key.KeyID, Attestation: key.Attestation, Storage: key.Storage}, p.now()))
	env, err := secchange.Sign(rec, priv)
	if err != nil {
		return "", err
	}
	raw, err := env.Marshal()
	if err != nil {
		return "", err
	}
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	row := store.ChangeRecordRow{
		ProjectID: root.ProjectID, ProjectRootHash: rootHash, CommitSHA: c.SHA, TreeSHA: tree, PatchFP: fp,
		KeyID: key.KeyID, AttestationLevel: key.Attestation, KeyStorage: key.Storage,
		RecordDigest: secchange.Digest(payload), Envelope: raw,
		Files: int64(len(rec.Files)), AILines: rec.Lines.AI, HumanLines: rec.Lines.Human, UnknownLines: rec.Lines.Unknown,
		HumanCapture: rec.Lines.HumanCapture, Sessions: rec.Sessions, Models: rec.Models, Tools: rec.Agents,
		Scanners: rec.Scanners, Packs: rec.PackVersions, Exceptions: rec.Exceptions,
		FindingsOpen: rec.Findings.Open, FindingsBlocking: rec.Findings.Blocking,
		CommittedAt: rec.CommittedAt, RecordedAt: rec.RecordedAt,
	}
	for _, f := range facts.Files {
		row.Paths = append(row.Paths, f.RelPath)
	}
	if rec.Evidence != nil {
		row.EvidenceDigest = rec.Evidence.Digest
	}
	if _, err := p.st.InsertChangeRecord(ctx, row); err != nil {
		return "", err
	}
	return provRecorded, nil
}

// loadFacts reads a commit's facts: from the attribution for HEAD's
// commits, and from the sandbox run's sessions for a commit a box returned
// (commitscan.Root.BoxRef, lane SEC-F2B).
func (p *provenanceSvc) loadFacts(ctx context.Context, root commitscan.Root, rootHash string, c commitlog.Commit) (store.ChangeFacts, store.ChangeFactsSkip, error) {
	if root.BoxRef == "" {
		return p.st.LoadChangeFacts(ctx, root.ProjectID, rootHash, c.SHA, p.linkWindow)
	}
	bc := store.BoxCommit{SHA: c.SHA, CommittedAt: c.CommittedAt}
	for _, f := range c.Files {
		if !f.Binary {
			bc.Files = append(bc.Files, store.ChangeFileFacts{PathHash: f.PathHash, RelPath: f.RelPath, Added: f.Added})
		}
	}
	return p.st.LoadBoxChangeFacts(ctx, root.ProjectID, rootHash, commitscan.BoxRunID(root.BoxRef), bc)
}

// provenanceOrgProject reads the facts the node already holds for the
// record's org binding (lane SEC-F2B): the org project id from the project
// audience's match record for root (cmd/observer/project_audience.go), when
// it is current for the cached bundle and names exactly one project, and
// the policy version as the cached org guard bundle's version
// ("guard-bundle:<n>"). Both are "" on a node that holds no project-scoped
// bundle, an unmatched or ambiguous root, or an unknown match.
func provenanceOrgProject(bundlePath, root string) (orgProjectID, policyVersion string) {
	if bundlePath == "" {
		return "", ""
	}
	composed, held := composedProjectBundle(bundlePath)
	if !held {
		return "", ""
	}
	if composed.Version > 0 {
		policyVersion = "guard-bundle:" + strconv.FormatInt(composed.Version, 10)
	}
	raw, err := os.ReadFile(projectmatch.LayoutFor(bundlePath).MatchPath(projectmatch.RootHash(root))) //nolint:gosec // G304: Observer's own match record.
	if err != nil {
		return "", policyVersion
	}
	m, err := projectmatch.DecodeMatchFile(raw)
	if err != nil || m.Unknown || !m.CurrentFor(composed.ProjectBinding, composed.Version) || len(m.OrgProjectIDs) != 1 {
		return "", policyVersion
	}
	return m.OrgProjectIDs[0], policyVersion
}

// provenanceBuildInput maps the store's facts onto the pure builder's
// input.
func provenanceBuildInput(f store.ChangeFacts, b secchange.Binding, k secchange.KeyRef, now time.Time) secchange.BuildInput {
	in := secchange.BuildInput{
		Binding: b, Key: k, CommittedAt: f.CommittedAt, RecordedAt: now,
		HumanCapture: f.HumanCapture, Sessions: f.Sessions, Agents: f.Tools, Models: f.Models,
		ToolVersions: f.ToolVersions, PromptIDs: f.PromptIDs, Scanners: f.Scanners, PackVersions: f.Packs,
		Exceptions:   f.Exceptions,
		Guard:        secchange.Guard{Events: f.GuardEvents, Denies: f.GuardDenies, Asks: f.GuardAsks, ApprovedAsks: f.GuardApprovedAsks},
		TaintAtWrite: f.Taint,
		Findings:     secchange.Findings{Open: f.FindingsOpen, Blocking: f.FindingsBlocking},
	}
	for _, x := range f.Files {
		in.Files = append(in.Files, secchange.FileInput{PathHash: x.PathHash, Added: x.Added, AI: x.AI, Human: x.Human})
	}
	if e := f.Evidence; e != nil {
		in.Evidence = &secchange.Evidence{RunID: e.RunID, Digest: e.Digest, IsolationClass: e.IsolationClass, CaptureLevel: e.CaptureLevel, KeyCustody: e.KeyCustody, Verification: e.Verification}
	}
	return in
}

// commitIdentity reads the commit's tree and its patch fingerprint (the
// stored one when the delivery step already computed it).
func (p *provenanceSvc) commitIdentity(ctx context.Context, root, sha string, f store.ChangeFacts) (tree, fp, state string, err error) {
	return provenanceCommitIdentity(ctx, p.git, root, sha, f.PatchFP, f.PatchFPState)
}

// provenanceCommitIdentity reads a commit's tree and patch fingerprint
// through the read-only envelope; storedFP is reused when its state is ok.
// Shared by the node builder and `observer security verify`.
func provenanceCommitIdentity(ctx context.Context, git provenanceGit, root, sha, storedFP, storedState string) (tree, fp, state string, err error) {
	out, _, err := git(ctx, root, 4096, provenanceGitTimeout, "rev-parse", "--verify", "--quiet", sha+"^{tree}")
	if err != nil {
		return "", "", "", fmt.Errorf("read the tree of %s: %w", sha, err)
	}
	tree = strings.TrimSpace(string(out))
	if storedState == string(commitlog.FingerprintOK) && storedFP != "" {
		return tree, storedFP, storedState, nil
	}
	diff, over, err := git(ctx, root, commitlog.MaxPatchBytes, provenanceGitTimeout,
		"diff-tree", "-p", "--no-renames", "-r", "--no-commit-id", "--root", sha)
	switch {
	case err != nil:
		return tree, "", "", fmt.Errorf("read the patch of %s: %w", sha, err)
	case over:
		return tree, "", string(commitlog.FingerprintTooLarge), nil
	}
	f, st := commitlog.PatchFingerprint(diff)
	return tree, f, string(st), nil
}

// newProvenanceOnCommit is the commit scanner's per-commit seam
// (commitscan_wire.go): a no-op unless the provenance loop runs.
func newProvenanceOnCommit(logger *slog.Logger) func(context.Context, commitscan.Root, commitlog.Commit) {
	return func(ctx context.Context, root commitscan.Root, c commitlog.Commit) {
		provenanceDecide(ctx, logger, root, c)
	}
}

// newProvenanceOnBoxCommit is the box ref half of the seam (lane SEC-F2B
// audit finding 4): true when the provenance loop decided the commit (its
// record written or already there, or none owed), false while the loop is
// off or when the record could not be made, so the scanner keeps the box
// ref's tip unremembered and offers its commits again.
func newProvenanceOnBoxCommit(logger *slog.Logger) func(context.Context, commitscan.Root, commitlog.Commit) bool {
	return func(ctx context.Context, root commitscan.Root, c commitlog.Commit) bool {
		return provenanceDecide(ctx, logger, root, c)
	}
}

// provenanceRunning reports whether the provenance loop runs (the commit
// scan lists box refs only then).
func provenanceRunning() bool { return provenanceRT.Load() != nil }

// provenanceDecide records one commit through the running provenance loop:
// false when the loop is off or the record could not be made.
func provenanceDecide(ctx context.Context, logger *slog.Logger, root commitscan.Root, c commitlog.Commit) bool {
	svc := provenanceRT.Load()
	if svc == nil {
		return false
	}
	out, err := svc.recordCommit(ctx, root, c)
	if err != nil {
		if logger != nil {
			logger.Warn("security provenance: record not made", "commit", c.SHA, "err", err)
		}
		return false
	}
	if out == provRecorded && logger != nil {
		logger.Info("security provenance: change record made", "commit", c.SHA)
	}
	return true
}

// provenanceChangeRecords is the org wire's change record provider
// (security_orgpush.go): the stored records while the provenance loop runs,
// nothing otherwise.
func provenanceChangeRecords(st *store.Store) func(context.Context, int, store.SecurityScope) ([]orgcontract.AIChangeRecordRow, error) {
	return func(ctx context.Context, max int, scope store.SecurityScope) ([]orgcontract.AIChangeRecordRow, error) {
		if provenanceRT.Load() == nil {
			return nil, nil
		}
		return st.SelectChangeRecordRows(ctx, max, scope)
	}
}

// startSecurityProvenance starts the provenance loop when the component is
// selected: it publishes the service the commit seam and the org wire read,
// and writes the consented git notes (security_provenance_writers.go).
func startSecurityProvenance(ctx context.Context, ng *gatedGroup, configPath string, snap componentstate.Snapshot) {
	if !provenanceSelected(snap) {
		return
	}
	ng.Go("security.provenance", func() error {
		cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
		if err != nil {
			slog.Default().Warn("security provenance: not started", "err", err)
			return nil
		}
		defer cleanup()
		logger := newLogger(cfg.Observer.LogLevel)
		svc := newProvenanceSvc(store.New(database), provenanceKeyDir(cfg), time.Duration(cfg.Projects.CommitLinkWindowDays)*24*time.Hour, logger)
		svc.bundlePath = orgBundleCachePath(cfg)
		svc.enrol = provenanceEnrollerFor(cfg, svc.st)
		// The key is made when the loop starts, so the first scan finds
		// every older commit "before provenance" without loading its
		// attribution.
		if _, _, err := svc.signingKey(ctx); err != nil {
			logger.Warn("security provenance: no signing key; no record is made until one can be stored", "err", err)
		}
		defer publishProvenance(ctx, svc, logger)()
		// The hook nudges a scan only while this flag exists (lane
		// SEC-F2B, security_provenance_nudge.go).
		if layoutDir, err := provenanceLayoutDir(configPath); err == nil {
			defer provenanceMarkActive(layoutDir)()
		}
		provenanceNotesLoop(ctx, svc)
		return nil
	})
}

// publishProvenance publishes svc to the commit seam and the org wire, then
// enrols its key with the org (a network call, so it runs after the
// publish: scanned commits get their records while it waits; lane SEC-F2B
// audit finding 4). The returned func withdraws svc.
func publishProvenance(ctx context.Context, svc *provenanceSvc, logger *slog.Logger) func() {
	provenanceRT.Store(svc)
	if err := svc.enrolKey(ctx); err != nil && logger != nil {
		logger.Warn("security provenance: key enrolment with the org failed; retried later", "err", err)
	}
	return func() { provenanceRT.CompareAndSwap(svc, nil) }
}

// errProvenanceOff is returned by the CLI and the dashboard when the
// component is not selected.
var errProvenanceOff = errors.New("AI change records (security.provenance) are off; turn the component on in Settings > Components or with `observer components add security.provenance`")
