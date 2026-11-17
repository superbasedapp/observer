package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
)

// compat_matrix_test.go is the plan 06 9.4 compatibility matrix for the
// retirement of the personal plane (D-IND-7; retired.go; docs/security.md
// IND-3), over PostgreSQL with the server bound to the sbci_api role:
//
//	node     control plane                 expectation
//	v1.38    E1 (SBCI_PERSONAL_PLANE=serving)   job submit / get, results, usage answer as before
//	v1.38    after M9 (retired)                 those answer 410 moved_to_org_plane with guidance;
//	                                            auth exchange, devices, consents, logout still work
//	v1.39+   either                             GET /v1/orgs and the personal ensure work; while
//	                                            serving, the old routes still answer
//
// The v1.38 requests are the shapes internal/cloudclient sends (client.go:
// POST /v1/jobs with Idempotency-Key and SBO-Feature and the exact envelope
// bytes; POST /v1/consents/preview-confirmation with previewConfirmWire's
// field names; GET /v1/jobs/{id}, /v1/results, /v1/usage, /v1/devices,
// /v1/consents; POST /v1/logout), each with the real bearer and cloudpop
// proof. The matrix stops at the API: a submitted job is admitted and queued,
// but no worker runs, so "results work" means the read answers 200 (with no
// results), not that an enrichment completes.

// compatState carries values between the steps of one row.
type compatState struct {
	envelope      []byte
	uploadDigest  string
	contentDigest string
	jobID         string
}

// compatStep is one node request and its expected status per control-plane
// mode. A 410 expectation also checks the moved_to_org_plane body.
type compatStep struct {
	name    string
	method  string
	path    func(st *compatState) string
	body    func(st *compatState) []byte
	headers map[string]string
	serving int
	retired int
	capture func(t *testing.T, st *compatState, raw []byte)
}

func fixedPath(p string) func(*compatState) string { return func(*compatState) string { return p } }

// unknownJobID stands in for a job id where no job was submitted (retired).
const unknownJobID = "00000000-0000-0000-0000-000000000000"

// v138Steps are a v1.38 node's personal-plane calls, in the order the node
// makes them; logout comes last.
var v138Steps = []compatStep{
	{
		name: "preview confirmation", method: "POST", path: fixedPath("/v1/consents/preview-confirmation"),
		body: func(st *compatState) []byte {
			b, _ := json.Marshal(map[string]any{
				"purposes":                []string{"structural_activity_insights"},
				"field_classes":           []string{"structural_metrics"},
				"evidence_schema":         cloudcontract.EnvelopeSchemaVersion,
				"scrubber_version":        "scrub-v1",
				"upload_digest":           st.uploadDigest,
				"evidence_content_digest": st.contentDigest,
			})
			return b
		},
		headers: map[string]string{"Content-Type": "application/json"},
		serving: http.StatusCreated, retired: http.StatusGone,
	},
	{
		name: "job submit (POST /v1/jobs)", method: "POST", path: fixedPath("/v1/jobs"),
		body: func(st *compatState) []byte { return st.envelope },
		headers: map[string]string{
			"Content-Type": "application/json", "Idempotency-Key": "compat-v138-idem-1",
			"SBO-Feature": "structural_activity_insights",
		},
		serving: http.StatusAccepted, retired: http.StatusGone,
		capture: func(t *testing.T, st *compatState, raw []byte) {
			var j struct {
				JobID string `json:"job_id"`
			}
			if err := json.Unmarshal(raw, &j); err != nil || j.JobID == "" {
				t.Fatalf("submit answer %s: %v", raw, err)
			}
			st.jobID = j.JobID
		},
	},
	{
		name: "job get (GET /v1/jobs/{id})", method: "GET",
		path: func(st *compatState) string {
			if st.jobID == "" {
				return "/v1/jobs/" + unknownJobID
			}
			return "/v1/jobs/" + st.jobID
		},
		serving: http.StatusOK, retired: http.StatusGone,
	},
	{name: "results", method: "GET", path: fixedPath("/v1/results"), serving: http.StatusOK, retired: http.StatusGone},
	{name: "usage", method: "GET", path: fixedPath("/v1/usage"), serving: http.StatusOK, retired: http.StatusGone},
	{name: "devices", method: "GET", path: fixedPath("/v1/devices"), serving: http.StatusOK, retired: http.StatusOK},
	{name: "consents", method: "GET", path: fixedPath("/v1/consents"), serving: http.StatusOK, retired: http.StatusOK},
	{name: "logout", method: "POST", path: fixedPath("/v1/logout"), serving: http.StatusOK, retired: http.StatusOK},
}

// v139Steps are the org discovery calls a v1.39+ node adds (observer
// connect), in any mode.
var v139Steps = []compatStep{
	{name: "org list", method: "GET", path: fixedPath("/v1/orgs"), serving: http.StatusOK, retired: http.StatusOK},
	{name: "personal ensure (creates)", method: "POST", path: fixedPath("/v1/orgs/personal:ensure"), serving: http.StatusCreated, retired: http.StatusCreated},
	{name: "personal ensure (exists)", method: "POST", path: fixedPath("/v1/orgs/personal:ensure"), serving: http.StatusOK, retired: http.StatusOK},
	{
		name: "org list (with the personal org)", method: "GET", path: fixedPath("/v1/orgs"), serving: http.StatusOK, retired: http.StatusOK,
		capture: func(t *testing.T, _ *compatState, raw []byte) {
			var l cloudcontract.DeviceOrgList
			if err := json.Unmarshal(raw, &l); err != nil {
				t.Fatalf("org list %s: %v", raw, err)
			}
			if err := l.Validate(); err != nil || len(l.Orgs) != 1 || l.Orgs[0].Kind != cloudcontract.DeviceOrgPersonal {
				t.Fatalf("org list = %+v (validate %v), want the one personal org", l, err)
			}
		},
	},
}

// compatRows are the matrix rows.
var compatRows = []struct {
	name  string
	plane string
	steps []compatStep
}{
	{"v1.38 node, E1 control plane (serving)", api.PersonalPlaneServing, v138Steps},
	{"v1.38 node, after M9 (retired)", api.PersonalPlaneRetired, v138Steps},
	{"v1.39+ node, serving: discovery, then the old routes", api.PersonalPlaneServing, append(append([]compatStep{}, v139Steps...), v138Steps...)},
	{"v1.39+ node, retired: discovery, the old routes moved", api.PersonalPlaneRetired, append(append([]compatStep{}, v139Steps...), v138Steps...)},
}

func TestPersonalPlaneCompatMatrix(t *testing.T) {
	for i, row := range compatRows {
		t.Run(row.name, func(t *testing.T) {
			h := newPlaneHarness(t, row.plane)
			// The v1.38 sign-in (nonce + exchange) must work in every mode:
			// h.login fails the test on anything but 200.
			c := h.login(t, "compat-node-"+string(rune('a'+i)))
			raw, ud, cd := makeEnvelope(t, false)
			st := &compatState{envelope: raw, uploadDigest: ud, contentDigest: cd}
			for _, step := range row.steps {
				want := step.serving
				if row.plane == api.PersonalPlaneRetired {
					want = step.retired
				}
				var body []byte
				if step.body != nil {
					body = step.body(st)
				}
				path := step.path(st)
				req := c.signedReq(step.method, path, body)
				for k, v := range step.headers {
					req.Header.Set(k, v)
				}
				resp := c.do(req)
				got := readAll(resp)
				if resp.StatusCode != want {
					t.Fatalf("%s (%s %s): status %d body=%s, want %d", step.name, step.method, path, resp.StatusCode, got, want)
				}
				if want == http.StatusGone {
					assertMovedBody(t, step.name, got)
					continue
				}
				if step.capture != nil {
					step.capture(t, st, []byte(got))
				}
			}
		})
	}
}

// assertMovedBody checks a 410 body a v1.38 node prints to its user.
func assertMovedBody(t *testing.T, label, raw string) {
	t.Helper()
	var b map[string]string
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		t.Fatalf("%s: 410 body %q: %v", label, raw, err)
	}
	if b["error"] != "moved_to_org_plane" || b["code"] != "moved_to_org_plane" ||
		!strings.Contains(b["message"], "observer connect") || !strings.Contains(b["message"], "1.39") || b["docs"] == "" {
		t.Fatalf("%s: 410 body = %v", label, b)
	}
}

// TestPortalPersonalPlaneField pins the console's view of the switch: the
// personal_plane field of the signed-out auth-config and the signed-in
// session, in both modes, and a retired portal read answering 410 while the
// org and browser-session reads keep serving.
func TestPortalPersonalPlaneField(t *testing.T) {
	for _, plane := range []string{api.PersonalPlaneServing, api.PersonalPlaneRetired} {
		t.Run(plane, func(t *testing.T) {
			h := newPlaneHarness(t, plane)
			resp, err := http.Get(h.srv.URL + "/portal/api/auth-config")
			if err != nil || resp.StatusCode != http.StatusOK {
				t.Fatalf("auth-config: %v", err)
			}
			var ac map[string]any
			decode(t, resp, &ac)
			if ac["personal_plane"] != plane {
				t.Fatalf("auth-config personal_plane = %v, want %q", ac["personal_plane"], plane)
			}
			pc := h.portalLogin(t, "plane-"+plane)
			var sess map[string]any
			decode(t, pc.get("/portal/api/session"), &sess)
			if sess["personal_plane"] != plane {
				t.Fatalf("session personal_plane = %v, want %q", sess["personal_plane"], plane)
			}
			wantOverview := http.StatusOK
			if plane == api.PersonalPlaneRetired {
				wantOverview = http.StatusGone
			}
			for _, tc := range []struct {
				path string
				want int
			}{
				{"/portal/api/overview", wantOverview},
				{"/portal/api/sessions", wantOverview},
				{"/portal/api/sessions/browser", http.StatusOK},
				{"/portal/api/orgs", http.StatusOK},
				{"/portal/api/consents", http.StatusOK},
			} {
				r := pc.get(tc.path)
				body := readAll(r)
				if r.StatusCode != tc.want {
					t.Errorf("%s: %d body=%s, want %d", tc.path, r.StatusCode, body, tc.want)
				} else if tc.want == http.StatusGone {
					assertMovedBody(t, tc.path, body)
				}
			}
		})
	}
}
