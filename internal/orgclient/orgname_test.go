package orgclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestPushAdoptsTheOrgsCurrentName is T-862's node half: an accepted push
// whose acknowledgment names the org's current display name replaces the name
// the enrolment stored; an acknowledgment without one (an older server) and
// one carrying an unusable name leave it alone.
func TestPushAdoptsTheOrgsCurrentName(t *testing.T) {
	s := newAgentStore(t)
	bs := &memBearerStore{}
	ackName := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, _ := io.ReadAll(r.Body)
		env := decodeEnvelope(t, wire)
		rows := int64(len(env.Sessions) + len(env.Actions) + len(env.APITurns) + len(env.TokenUsage))
		writeTestJSON(w, http.StatusOK, orgcontract.PushResponse{
			AcceptedRows: rows, NextCursor: env.CursorTo, OrgName: ackName,
		})
	}))
	defer srv.Close()
	pub := enrolFixture(t, s, bs, srv.URL)
	bindPub(srv, pub)
	c := newTestClient(t, s, bs)
	ctx := context.Background()

	steps := []struct {
		name, ack, want string
	}{
		{"an older server sends no name", "", "Acme"},
		{"the admin renamed the org", "Acme Robotics", "Acme Robotics"},
		{"an unusable name is ignored", "Evil\nName", "Acme Robotics"},
		{"the same name again is a no-op", "Acme Robotics", "Acme Robotics"},
	}
	for i, st := range steps {
		ackName = st.ack
		seedActivity(t, s, i+1)
		if _, err := c.PushOnce(ctx); err != nil {
			t.Fatalf("%s: PushOnce: %v", st.name, err)
		}
		enr, err := s.LoadEnrolment(ctx)
		if err != nil || enr == nil {
			t.Fatalf("%s: LoadEnrolment: %v", st.name, err)
		}
		if enr.OrgName != st.want {
			t.Errorf("%s: enrolment org name = %q, want %q", st.name, enr.OrgName, st.want)
		}
		st2, err := c.Status(ctx)
		if err != nil || st2.OrgName != st.want {
			t.Errorf("%s: Status org name = %q (%v), want %q", st.name, st2.OrgName, err, st.want)
		}
	}
}
