package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// TestStaffSixthPasskeyIsRefused drives ruling Staff 2 (L-83) over HTTP on
// the staff process against Postgres: four more passkeys register after the
// first, and the sixth enrolment code's redemption answers 409 passkey_limit
// with a sentence naming the cap and the remedy, logged as a refused
// credential.registered row.
func TestStaffSixthPasskeyIsRefused(t *testing.T) {
	t.Parallel()
	h := newStaffPGHarness(t)
	staffID, _, _, _ := h.staff(staffauth.RoleAdmin, api.NewStaffTestAuthenticator(40))
	ctx := context.Background()
	register := func(seed byte) *httptest.ResponseRecorder {
		t.Helper()
		e, err := h.app.EnrolStaff(ctx, store.EnrolStaffInput{StaffID: staffID, Reason: "another key", Now: time.Now()})
		if err != nil {
			t.Fatalf("EnrolStaff: %v", err)
		}
		begin := h.do("POST", "/staff/auth/webauthn/register/begin", map[string]string{"enrolment_code": e.RawCode}, nil, nil)
		if begin.Code != http.StatusOK {
			return begin
		}
		var co struct {
			PublicKey staffauth.CreationOptions `json:"publicKey"`
		}
		if err := json.Unmarshal(begin.Body.Bytes(), &co); err != nil {
			t.Fatal(err)
		}
		return h.do("POST", "/staff/auth/webauthn/register/finish",
			map[string]any{"credential": api.NewStaffTestAuthenticator(seed).Register(co.PublicKey.Challenge, staffPGOrigin)},
			[]*http.Cookie{recCookie(begin, "__Host-sbci-staff-ceremony")}, nil)
	}
	for seed := byte(41); seed <= 44; seed++ {
		if rec := register(seed); rec.Code != http.StatusCreated {
			t.Fatalf("passkey %d: %d %s", seed-39, rec.Code, rec.Body)
		}
	}
	rec := register(45)
	if rec.Code != http.StatusConflict {
		t.Fatalf("sixth passkey: %d %s, want 409", rec.Code, rec.Body)
	}
	var body struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "passkey_limit" || !strings.Contains(body.Error, "5 active passkeys") || !strings.Contains(body.Error, "revoke-credential") {
		t.Errorf("refusal = %+v", body)
	}
	acts, err := h.app.ListStaffActions(ctx, 200)
	if err != nil {
		t.Fatal(err)
	}
	logged := false
	for _, a := range acts {
		if a.Verb == string(staffauth.VerbCredentialRegistered) && a.Result == "refused" && a.SubjectStaffID == staffID {
			logged = true
		}
	}
	if !logged {
		t.Error("the refused sixth passkey left no refused credential.registered row")
	}
}
