package hostclient_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi/hostclient"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// remoteSigner stands in for the document signer's sign_request operation:
// it signs with priv and lets a test tamper with the envelope it returns.
func remoteSigner(priv ed25519.PrivateKey, keyID string, tamper func(*pc.Envelope)) hostclient.EnvelopeSignFunc {
	return func(_ context.Context, method, target, nonce, digest string, ts int64) (pc.Envelope, error) {
		e := pc.Envelope{KeyID: keyID, Timestamp: ts, Nonce: nonce, BodyDigest: digest}
		in, err := pc.SigningInput(method, target, e)
		if err != nil {
			return pc.Envelope{}, err
		}
		e.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, in))
		if tamper != nil {
			tamper(&e)
		}
		return e, nil
	}
}

func signingInputFor(t *testing.T, keyID string) []byte {
	t.Helper()
	in, err := pc.SigningInput("PUT", pc.BasePath+"/tenants/x/state",
		pc.Envelope{KeyID: keyID, Timestamp: testNow.Unix(), Nonce: "n-1", BodyDigest: pc.BodyDigest([]byte(`{}`))})
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// TestEnvelopeRequestSigner: the adapter returns the remote signature only
// when the envelope repeats what was asked and verifies under the pinned key.
func TestEnvelopeRequestSigner(t *testing.T) {
	t.Parallel()
	const kid = "host-api-1"
	cases := []struct {
		name    string
		signer  hostclient.EnvelopeSignFunc
		input   func(t *testing.T) []byte
		wantErr error
	}{
		{name: "verified", signer: remoteSigner(requestKey, kid, nil), input: func(t *testing.T) []byte { return signingInputFor(t, kid) }},
		{
			name: "another key id in the input", signer: remoteSigner(requestKey, kid, nil),
			input: func(t *testing.T) []byte { return signingInputFor(t, "other") }, wantErr: hostclient.ErrSignerMismatch,
		},
		{
			name: "not a signing input", signer: remoteSigner(requestKey, kid, nil),
			input: func(*testing.T) []byte { return []byte("a\nb") }, wantErr: hostclient.ErrSignerMismatch,
		},
		{
			name: "answer for another nonce", signer: remoteSigner(requestKey, kid, func(e *pc.Envelope) { e.Nonce = "n-2" }),
			input: func(t *testing.T) []byte { return signingInputFor(t, kid) }, wantErr: hostclient.ErrSignerMismatch,
		},
		{
			name: "answer with a rotated key id", signer: remoteSigner(requestKey, kid, func(e *pc.Envelope) { e.KeyID = "host-api-2" }),
			input: func(t *testing.T) []byte { return signingInputFor(t, kid) }, wantErr: hostclient.ErrSignerMismatch,
		},
		{
			name: "signature by another key", signer: remoteSigner(key("someone else"), kid, nil),
			input: func(t *testing.T) []byte { return signingInputFor(t, kid) }, wantErr: hostclient.ErrSignerMismatch,
		},
		{name: "signer error", signer: func(context.Context, string, string, string, string, int64) (pc.Envelope, error) {
			return pc.Envelope{}, errBoom
		}, input: func(t *testing.T) []byte { return signingInputFor(t, kid) }, wantErr: errBoom},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rs, err := hostclient.EnvelopeRequestSigner(kid, pub(requestKey), tc.signer)
			if err != nil {
				t.Fatal(err)
			}
			in := tc.input(t)
			sig, err := rs.Sign(context.Background(), in)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) || sig != nil {
					t.Fatalf("Sign = %x, %v; want %v", sig, err, tc.wantErr)
				}
				return
			}
			if err != nil || !ed25519.Verify(pub(requestKey), in, sig) {
				t.Fatalf("Sign = %x, %v; want a verifying signature", sig, err)
			}
		})
	}
}

func TestEnvelopeRequestSignerRefusesBadConstruction(t *testing.T) {
	t.Parallel()
	ok := remoteSigner(requestKey, "k", nil)
	for name, build := range map[string]func() (hostclient.RequestSigner, error){
		"empty key id": func() (hostclient.RequestSigner, error) {
			return hostclient.EnvelopeRequestSigner(" ", pub(requestKey), ok)
		},
		"newline key id": func() (hostclient.RequestSigner, error) {
			return hostclient.EnvelopeRequestSigner("a\nb", pub(requestKey), ok)
		},
		"short public key": func() (hostclient.RequestSigner, error) { return hostclient.EnvelopeRequestSigner("k", []byte{1}, ok) },
		"no sign function": func() (hostclient.RequestSigner, error) {
			return hostclient.EnvelopeRequestSigner("k", pub(requestKey), nil)
		},
	} {
		if _, err := build(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
