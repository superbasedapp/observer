//go:build !sbo_omit_security

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/secchange"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_provenance_enrol.go is a managed node's half of key enrolment
// (security plan 7.10 "Key enrolment", lane SEC-F2B): the provenance loop
// registers the active signing key with the org over the enrolled channel
// (orgclient.EnrolChangeKey) and keeps the org's verified certificate
// beside the key files, so records the key signs carry org_certified and
// `--export-keys` hands CI the org root and the certificate. An individual
// node self-certifies and never calls the org. A server without
// org.security.ci answers 404 and the key stays self-attested.

// provenanceEnroller is the enrolment call (orgclient.Client.EnrolChangeKey).
type provenanceEnroller func(ctx context.Context, priv ed25519.PrivateKey, machine string, now time.Time) (orgclient.ChangeKeyCertificate, error)

// provenanceEnrolRetry spaces enrolment attempts after a failure.
const provenanceEnrolRetry = time.Hour

// provenanceEnrolNoMachineRetry spaces enrolment attempts while the org has
// no machine on record for this member (lane SEC-P4 decision 8): the next
// push names it, so the node asks again soon after.
const provenanceEnrolNoMachineRetry = 10 * time.Minute

// provenanceCertRenew re-enrols a key whose certificate runs out within
// this window.
const provenanceCertRenew = 14 * 24 * time.Hour

// provenanceKeyCert is a kept certificate: verified under its org root,
// for this key, org and machine.
type provenanceKeyCert struct {
	Certificate secchange.Certificate `json:"certificate"`
	OrgRoot     secchange.TrustKey    `json:"org_root"`
}

// provenanceVerifyCert checks the org's answer: the certificate verifies
// under the org root the org client already matched to the pinned org key,
// and names exactly this key, org and machine.
func provenanceVerifyCert(ans orgclient.ChangeKeyCertificate, keyID, orgID, machine string) (provenanceKeyCert, error) {
	var c secchange.Certificate
	if err := json.Unmarshal(ans.Certificate, &c); err != nil {
		return provenanceKeyCert{}, orgclient.ErrChangeKeyCertificate
	}
	root := secchange.TrustKey{KeyID: ans.OrgRoot.KeyID, PublicKey: ans.OrgRoot.PublicKey}
	ts, err := secchange.NewTrustSet(secchange.TrustFile{Version: secchange.TrustVersion, OrgRoots: []secchange.TrustKey{root}, Certificates: []secchange.Certificate{c}})
	if err != nil || ts.Len() != 1 || len(ts.Issues) != 0 || c.KeyID != keyID || c.OrgID != orgID || c.MachineIdentity != machine {
		return provenanceKeyCert{}, orgclient.ErrChangeKeyCertificate
	}
	return provenanceKeyCert{Certificate: c, OrgRoot: root}, nil
}

// provenanceCertPath is where a key's certificate is kept.
func provenanceCertPath(keyDir, keyID string) string {
	return filepath.Join(keyDir, "cert-"+keyID+".json")
}

// provenanceLoadCert reads a key's kept certificate (ok false when none).
func provenanceLoadCert(keyDir, keyID string) (provenanceKeyCert, bool) {
	var c provenanceKeyCert
	if keyDir == "" {
		return c, false
	}
	b, err := os.ReadFile(provenanceCertPath(keyDir, keyID)) //nolint:gosec // G304: Observer's own key directory.
	if err != nil || json.Unmarshal(b, &c) != nil || c.Certificate.KeyID != keyID {
		return provenanceKeyCert{}, false
	}
	return c, true
}

// enrolKey enrols the active key when the node is managed and holds no
// certificate for it that is good for provenanceCertRenew more; it never
// rotates or touches the key. Errors are the caller's to log.
func (p *provenanceSvc) enrolKey(ctx context.Context) error {
	if p.enrol == nil {
		return nil
	}
	now := p.now()
	if !p.nextEnrol.IsZero() && now.Before(p.nextEnrol) {
		return nil
	}
	_, orgID, machine, err := p.provenanceEnrolment(ctx)
	if err != nil || orgID == "" || machine == "" {
		return err
	}
	priv, key, err := p.signingKey(ctx)
	if err != nil {
		return err
	}
	if c, ok := provenanceLoadCert(p.keyDir, key.KeyID); ok {
		if na, perr := time.Parse(time.RFC3339, c.Certificate.NotAfter); perr == nil && now.Add(provenanceCertRenew).Before(na) {
			return nil
		}
	}
	ans, err := p.enrol(ctx, priv, machine, now)
	switch {
	case errors.Is(err, orgclient.ErrChangeKeyNotSupported), errors.Is(err, orgclient.ErrChangeKeyIndividual):
		p.nextEnrol = now.Add(24 * time.Hour)
		return nil
	case errors.Is(err, orgclient.ErrChangeKeyMachineBound):
		// The member's keys are bound to another machine (lane
		// LEFT-SHARED): the key stays self-attested; retry daily in case
		// an admin reset the binding.
		p.nextEnrol = now.Add(24 * time.Hour)
		return err
	case errors.Is(err, orgclient.ErrChangeKeyMachineNotOnRecord):
		// Not an error: the key stays self-attested until the first push
		// puts this machine on record, then the next attempt certifies it.
		p.nextEnrol = now.Add(provenanceEnrolNoMachineRetry)
		return nil
	case err != nil:
		p.nextEnrol = now.Add(provenanceEnrolRetry)
		return err
	}
	cert, err := provenanceVerifyCert(ans, key.KeyID, orgID, machine)
	if err != nil {
		p.nextEnrol = now.Add(provenanceEnrolRetry)
		return err
	}
	b, err := json.Marshal(cert)
	if err != nil {
		return err
	}
	if p.keyDir != "" {
		if err := os.MkdirAll(p.keyDir, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(provenanceCertPath(p.keyDir, key.KeyID), b, 0o600); err != nil {
			return err
		}
	}
	p.logger.Info("security provenance: signing key certified by the org", "key_id", key.KeyID, "not_after", cert.Certificate.NotAfter)
	return p.st.SetChangeKeyAttestation(ctx, key.KeyID, secchange.AttestationOrg)
}

// provenanceAddCertificates adds the kept certificates and their org roots
// to a keys file (`--export-keys`), so CI trusts the org's certificate.
func provenanceAddCertificates(f *secchange.TrustFile, keyDir string, keys []store.ChangeKey) {
	seen := map[string]bool{}
	for _, k := range keys {
		c, ok := provenanceLoadCert(keyDir, k.KeyID)
		if !ok {
			continue
		}
		f.Certificates = append(f.Certificates, c.Certificate)
		if !seen[c.OrgRoot.KeyID] {
			seen[c.OrgRoot.KeyID] = true
			f.OrgRoots = append(f.OrgRoots, c.OrgRoot)
		}
	}
}

// provenanceEnrollerFor builds the enrolment call over a short-lived org
// client (the projectResolveCall precedent): the bearer store opens only
// when a call is made.
func provenanceEnrollerFor(cfg config.Config, st *store.Store) provenanceEnroller {
	return func(ctx context.Context, priv ed25519.PrivateKey, machine string, now time.Time) (orgclient.ChangeKeyCertificate, error) {
		bs := orgclient.OpenBearerStoreQuiet(cfg.OrgClient.KeychainID, filepath.Dir(cfg.Observer.DBPath))
		return orgclient.New(cfg.OrgClient, st, bs, version, nil, nil).EnrolChangeKey(ctx, priv, machine, now)
	}
}
