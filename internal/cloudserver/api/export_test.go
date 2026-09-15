package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// export_test.go covers the W6d export HTTP surface (plan §3 W6d; D11): the
// device assemble+download, cross-account non-disclosure, expiry (410), and the
// portal reauth-gated assemble + list + download.

// TestExportDeviceAssembleAndDownload: POST /v1/export assembles; GET
// /v1/exports/{id} downloads the JSON as an attachment.
func TestExportDeviceAssembleAndDownload(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "exp-dave")

	resp := c.do(c.signedReq("POST", "/v1/export", []byte(`{}`)))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /v1/export status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var er struct {
		ExportID  string    `json:"export_id"`
		SizeBytes int64     `json:"size_bytes"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	decode(t, resp, &er)
	if er.ExportID == "" || er.SizeBytes <= 0 {
		t.Fatalf("bad export response: %+v", er)
	}

	dl := c.do(c.signedReq("GET", "/v1/exports/"+er.ExportID, nil))
	if dl.StatusCode != http.StatusOK {
		t.Fatalf("download status=%d body=%s", dl.StatusCode, readAll(dl))
	}
	if cd := dl.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.Contains(cd, er.ExportID) {
		t.Errorf("Content-Disposition = %q, want attachment naming the export", cd)
	}
	if ct := dl.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := readAll(dl)
	var doc cloudcontract.AccountExport
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("download is not a valid export: %v", err)
	}
	if doc.AccountID != c.accountID {
		t.Fatalf("export account_id = %q, want %q", doc.AccountID, c.accountID)
	}
}

// TestExportDeviceCrossAccountNotFound: a device cannot download another
// account's export — RLS makes it a 404 (non-disclosure).
func TestExportDeviceCrossAccountNotFound(t *testing.T) {
	h := newHarness(t)
	a := h.login(t, "exp-alice")
	b := h.login(t, "exp-bob")

	resp := a.do(a.signedReq("POST", "/v1/export", []byte(`{}`)))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("assemble status=%d", resp.StatusCode)
	}
	var er struct {
		ExportID string `json:"export_id"`
	}
	decode(t, resp, &er)

	// B tries to download A's export id.
	if dl := b.do(b.signedReq("GET", "/v1/exports/"+er.ExportID, nil)); dl.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-account download status=%d, want 404", dl.StatusCode)
	}
}

// TestExportDeviceExpiredGone: a download past the artifact TTL is 410 Gone.
func TestExportDeviceExpiredGone(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "exp-erin")

	// Assemble an already-expired artifact directly through the store (dated in
	// the past), then download via the device path.
	past := time.Now().Add(-store.ExportArtifactTTL - time.Hour)
	meta, err := h.store.CreateExportArtifact(context.Background(), c.accountID, past)
	if err != nil {
		t.Fatalf("CreateExportArtifact(past): %v", err)
	}
	if dl := c.do(c.signedReq("GET", "/v1/exports/"+meta.ID, nil)); dl.StatusCode != http.StatusGone {
		t.Fatalf("expired download status=%d, want 410", dl.StatusCode)
	}
}

// TestExportPortalReauthAssembleListDownload: the portal assemble requires
// reauth (dev-auth = re-present a matching broker credential), then the export
// lists and downloads over the session.
func TestExportPortalReauthAssembleListDownload(t *testing.T) {
	h := newHarness(t)
	pc := h.portalLogin(t, "exp-portal")

	// Wrong reauth credential ⇒ 403.
	if resp := pc.mutate("POST", "/portal/api/exports", []byte(`{"broker_token":"dev:someone-else"}`), pc.csrf); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("mismatched reauth status=%d, want 403", resp.StatusCode)
	}
	// Missing CSRF ⇒ 403 (the mutation guard, before reauth).
	if resp := pc.mutate("POST", "/portal/api/exports", []byte(`{"broker_token":"dev:exp-portal"}`), ""); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing-CSRF status=%d, want 403", resp.StatusCode)
	}

	// Correct reauth ⇒ 201.
	resp := pc.mutate("POST", "/portal/api/exports", []byte(`{"broker_token":"dev:exp-portal"}`), pc.csrf)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("portal assemble status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var er struct {
		ExportID string `json:"export_id"`
	}
	decode(t, resp, &er)
	if er.ExportID == "" {
		t.Fatal("portal assemble returned no export id")
	}

	// The list shows it.
	list := pc.get("/portal/api/exports")
	if list.StatusCode != http.StatusOK {
		t.Fatalf("list status=%d", list.StatusCode)
	}
	var lr struct {
		Exports []struct {
			ExportID string `json:"export_id"`
		} `json:"exports"`
	}
	decode(t, list, &lr)
	found := false
	for _, e := range lr.Exports {
		if e.ExportID == er.ExportID {
			found = true
		}
	}
	if !found {
		t.Fatalf("assembled export %s not in the list %+v", er.ExportID, lr.Exports)
	}

	// The download returns the JSON over the session.
	dl := pc.get("/portal/api/exports/" + er.ExportID + "/download")
	if dl.StatusCode != http.StatusOK {
		t.Fatalf("portal download status=%d body=%s", dl.StatusCode, readAll(dl))
	}
	var doc cloudcontract.AccountExport
	if err := json.Unmarshal([]byte(readAll(dl)), &doc); err != nil {
		t.Fatalf("portal download not a valid export: %v", err)
	}
	if doc.AccountID != pc.accountID {
		t.Fatalf("export account_id = %q, want %q", doc.AccountID, pc.accountID)
	}
}
