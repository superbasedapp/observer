package orgclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestEnrollClearsEveryIdentityBoundCache pins T-393: a re-enrolment into
// another org, or as another member, drops every identity-bound cache (the
// durable documents, the hot caches, the break-glass slot and the sidecar and
// bundle files); a re-enrolment as the same org and member keeps them.
func TestEnrollClearsEveryIdentityBoundCache(t *testing.T) {
	cases := []struct {
		name     string
		orgID    string
		userID   string
		wantKept bool
	}{
		{"same org and member", "org-1", "scim-42", true},
		{"another org", "org-2", "scim-42", false},
		{"another member", "org-1", "scim-77", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newAgentStore(t)
			bs := &leaseBearerStore{}
			c := newTestClient(t, s, bs)
			dir := t.TempDir()
			bundle := filepath.Join(dir, "org-bundle.json")
			sidecar := filepath.Join(dir, "governance.json")
			features := filepath.Join(dir, "features.json")
			c.SetGuardBundleCachePath(bundle)
			c.SetGovernanceSidecarPath(sidecar)
			c.featuresSidecarPath = features
			ctx := context.Background()
			resp := orgcontract.EnrollResponse{
				Bearer: "bearer-1", BearerExpiresAt: "2026-12-01T00:00:00Z",
				OrgID: "org-1", OrgName: "Acme", UserID: "scim-42", UserEmail: "dev@acme.example", Tenancy: "managed",
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writeTestJSON(w, http.StatusOK, resp)
			}))
			defer srv.Close()
			if _, _, err := c.Enroll(ctx, srv.URL, "tok_id.secret"); err != nil {
				t.Fatalf("first Enroll: %v", err)
			}

			now := time.Now().UTC()
			if err := s.UpsertOrgDisplayPolicy(ctx, store.OrgDisplayPolicyRow{OrgID: "org-1", Version: 4, Body: "{}", BodyHash: "h", Signature: "s", ServerPubkey: "k", DeveloperCostDisplay: "tokens", ReceivedAt: now}); err != nil {
				t.Fatal(err)
			}
			if err := s.UpsertOrgRoutingPolicy(ctx, store.OrgRoutingPolicyRow{Version: 3, Body: "[routing]\n", BodyHash: "h", Signature: "s", ServerPubkey: "k", ReceivedAt: now}); err != nil {
				t.Fatal(err)
			}
			if err := s.UpsertOrgAnnouncement(ctx, store.OrgAnnouncementRow{Version: 7, Body: `{"id":"x"}`, BodyHash: "h", Signature: "s", ServerPubkey: "k", ReceivedAt: now}); err != nil {
				t.Fatal(err)
			}
			if err := s.SaveOrgPolicyETag(ctx, `"etag-1"`); err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{bundle, sidecar, features} {
				if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			bs.leases = []byte(`[{"lease_id":"l1"}]`)
			pinUpdateKeyForTest(c, "update-key-org-1")

			resp.OrgID, resp.UserID, resp.Bearer = tc.orgID, tc.userID, "bearer-2"
			if _, _, err := c.Enroll(ctx, srv.URL, "tok_id.secret2"); err != nil {
				t.Fatalf("re-Enroll: %v", err)
			}

			kept := map[string]bool{}
			_, kept["display policy"], _ = s.GetOrgDisplayPolicy(ctx)
			_, kept["routing policy"], _ = s.GetOrgRoutingPolicy(ctx)
			_, kept["announcement"], _ = s.GetOrgAnnouncement(ctx)
			etag, _ := s.LoadOrgPolicyETag(ctx)
			kept["guard bundle ETag"] = etag != ""
			for name, p := range map[string]string{"guard bundle file": bundle, "governance sidecar": sidecar, "features sidecar": features} {
				_, err := os.Stat(p)
				kept[name] = err == nil
			}
			kept["break-glass slot"] = len(bs.leases) > 0
			if pinned, ok := updateKeyPinnedForTest(c); ok {
				kept["update key pin"] = pinned
			}
			var wrong []string
			for name, k := range kept {
				if k != tc.wantKept {
					wrong = append(wrong, name)
				}
			}
			sort.Strings(wrong)
			if len(wrong) > 0 {
				t.Fatalf("after re-enrol (want kept=%v) these disagree: %s", tc.wantKept, strings.Join(wrong, ", "))
			}
		})
	}
}

// writerDecision is one store writer this package calls: either the
// identity-bound document that clears it, or the reason it needs no clear.
type writerDecision struct {
	clearedBy store.IdentityBoundDoc
	reason    string
}

// orgclientStoreWriters records a decision for every store writer the
// package calls (T-393). A new writer without a row fails
// TestEveryOrgclientStoreWriterHasAnIdentityDecision.
var orgclientStoreWriters = map[string]writerDecision{
	"SaveAccessGrants":            {clearedBy: store.IdentityDocAccessGrants},
	"TouchAccessGrantsVerified":   {clearedBy: store.IdentityDocAccessGrants},
	"NoteOutboxAttempt":           {clearedBy: store.IdentityDocAccessGrants},
	"UpsertOrgAgentConfigPolicy":  {clearedBy: store.IdentityDocAgentConfig},
	"UpsertOrgAnnouncement":       {clearedBy: store.IdentityDocAnnouncements},
	"UpsertOrgDisplayPolicy":      {clearedBy: store.IdentityDocDisplayPolicy},
	"UpsertOrgRoutingPolicy":      {clearedBy: store.IdentityDocRoutingPolicy},
	"UpsertOrgIntelRequirement":   {clearedBy: store.IdentityDocIntel},
	"UpsertOrgIntelResult":        {clearedBy: store.IdentityDocIntel},
	"MarkOrgIntelSubmission":      {clearedBy: store.IdentityDocIntel},
	"SaveOrgPricingRaw":           {clearedBy: store.IdentityDocPricing},
	"SaveOrgBudgetWithWitness":    {clearedBy: store.IdentityDocBudget},
	"SaveOrgPolicyETag":           {clearedBy: store.IdentityDocGuardETag},
	"SaveVerifiedManifest":        {clearedBy: store.IdentityDocUpdateManifest},
	"SaveOrgMessagePage":          {clearedBy: store.IdentityDocMessages},
	"NoteOrgMessageFetch":         {clearedBy: store.IdentityDocMessages},
	"NoteOrgMessageOutboxAttempt": {clearedBy: store.IdentityDocMessages},
	"MarkOrgMessageOutboxSent":    {clearedBy: store.IdentityDocMessages},
	"MarkOrgMessageThreadRead":    {clearedBy: store.IdentityDocMessages},
	"SetSecurityOrgPurpose":       {clearedBy: store.IdentityDocSecurityPurpose},
	"SetSecurityOrgVisibility":    {clearedBy: store.IdentityDocSecurityPurpose},

	"WriteEnrolment":                  {reason: "the enrolment row itself"},
	"SetEnrolmentOrgName":             {reason: "a column of the enrolment row itself, and the write is bound to that row's org id; Enroll's WriteEnrolment rewrites the name and unenroll deletes the row"},
	"BumpEnrolmentGeneration":         {reason: "the identity fence itself"},
	"ReplaceEnrolmentGrant":           {reason: "keyed by org key and fenced by the enrolment generation (P0-5)"},
	"SavePolicyResourceETag":          {reason: "keyed by org key; Enroll runs ClearPolicyResourceState for the old key"},
	"SaveManagedPull":                 {reason: "keyed by org key and enrolment generation; LoadManagedPull reads another identity's row as absent, and the stored document is re-verified against this node's org and subject"},
	"RecordGuardPolicyState":          {reason: "append-only pin history keyed by org URL; Enroll re-pins the trust root"},
	"ReplaceOrgProjectMappingIndex":   {reason: "replaced whole by every accepted v3 delivery, whose gate binds the mapping to this enrolment's org and subject; the daemon matcher uses a row only while its epoch and digest equal the composed bundle in force"},
	"RecordOrgIntelTombstonesApplied": {reason: "the node's own intel audit"},
	"RecordPush":                      {reason: "the node's own push history"},
	"SaveLastPushPayload":             {reason: "the node's own push payload; Enroll clears the last-push state"},
	"SavePushCursor":                  {reason: "Enroll reseeds the push cursor"},
	"SavePushCursorIfUnchanged":       {reason: "Enroll reseeds the push cursor"},
	"CommitPushedSnapshots":           {reason: "push re-send tracking, the node's own data"},
	"SetBudgetPostureProvider":        {reason: "an in-process provider, not a cache"},
	"SetComponentPostureProvider":     {reason: "an in-process provider, not a cache; its delivered digest is re-sent at least every 6h, so a re-enrolment converges"},
}

// writerCall matches a store call this package makes; writerVerb keeps the
// ones that write (clearers and readers need no decision).
var (
	writerCall = regexp.MustCompile(`c\.store\.([A-Z][A-Za-z0-9]*)\(`)
	writerVerb = regexp.MustCompile(`^(Save|Upsert|Replace|Record|Append|Write|Touch|Note|Put|Insert|Set|Mark|Consume|Bump|Commit|Store|Apply|Advance)`)
)

// TestEveryOrgclientStoreWriterHasAnIdentityDecision scans this package's
// non-test sources for store writers and fails when one has no decision, when
// a decision names a document the store no longer clears, or when a decision
// is left for a writer the package no longer calls.
func TestEveryOrgclientStoreWriterHasAnIdentityDecision(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range writerCall.FindAllStringSubmatch(string(src), -1) {
			if writerVerb.MatchString(m[1]) {
				seen[m[1]] = true
			}
		}
	}
	docs := map[store.IdentityBoundDoc]bool{}
	for _, d := range store.IdentityBoundDocs() {
		docs[d] = true
	}
	var missing []string
	for w := range seen {
		d, ok := orgclientStoreWriters[w]
		if !ok {
			missing = append(missing, w)
			continue
		}
		if d.clearedBy != "" && !docs[d.clearedBy] {
			t.Errorf("writer %s is cleared by %q, which store.ClearIdentityBoundDocs does not clear", w, d.clearedBy)
		}
		if d.clearedBy == "" && d.reason == "" {
			t.Errorf("writer %s has neither a clearing document nor a reason", w)
		}
	}
	sort.Strings(missing)
	for _, w := range missing {
		t.Errorf("store writer %s has no identity decision: add it to orgclientStoreWriters (cleared by an identity-bound document, or the reason it needs none)", w)
	}
	for w := range orgclientStoreWriters {
		if !seen[w] {
			t.Errorf("orgclientStoreWriters lists %s, which this package no longer calls", w)
		}
	}
}

// TestIdentityBoundDocsNameTheBriefedCaches pins the documents the T-393 brief
// names explicitly, so a refactor cannot drop one silently.
func TestIdentityBoundDocsNameTheBriefedCaches(t *testing.T) {
	have := map[store.IdentityBoundDoc]bool{}
	for _, d := range store.IdentityBoundDocs() {
		have[d] = true
	}
	for _, want := range []store.IdentityBoundDoc{
		store.IdentityDocDisplayPolicy, store.IdentityDocRoutingPolicy, store.IdentityDocAnnouncements,
		store.IdentityDocBudget, store.IdentityDocAccessGrants, store.IdentityDocIntel,
		store.IdentityDocAgentConfig, store.IdentityDocPricing, store.IdentityDocGuardETag, store.IdentityDocUpdateManifest,
	} {
		if !have[want] {
			t.Errorf("store.ClearIdentityBoundDocs no longer clears %q", want)
		}
	}
	var sawStore bool
	for _, ic := range identityBoundCaches {
		if ic.name == "identity-bound org documents" && ic.scope == clearOnIdentityChange {
			sawStore = true
		}
	}
	if !sawStore {
		t.Error("identityBoundCaches no longer defers to store.ClearIdentityBoundDocs on an identity change")
	}
}
