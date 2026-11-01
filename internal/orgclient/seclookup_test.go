package orgclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

func TestSecurityLookup(t *testing.T) {
	status := http.StatusOK
	var got orgcontract.SecurityLookupRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != orgcontract.AgentSecurityLookupPath || r.Method != http.MethodPost || r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		writeTestJSON(w, http.StatusOK, orgcontract.SecurityLookupResponse{Mode: "relay", Answers: []orgcontract.SecurityLookupAnswer{
			{Ecosystem: "npm", Name: "left-pad", Status: "answered"},
			{Ecosystem: "npm", Name: "not-asked", Status: "answered"},
		}})
	}))
	defer srv.Close()
	c, _, _ := enrolledClient(t, srv.URL)
	in := orgcontract.SecurityLookupRequest{Queries: []orgcontract.SecurityLookupQuery{{Ecosystem: "npm", Name: "left-pad"}}}
	out, err := c.SecurityLookup(context.Background(), in)
	if err != nil || out.Mode != "relay" || len(out.Answers) != 1 || out.Answers[0].Name != "left-pad" {
		t.Fatalf("lookup %+v %v", out, err)
	}
	if len(got.Queries) != 1 || got.Queries[0].Name != "left-pad" {
		t.Errorf("sent %+v", got)
	}
	status = http.StatusNotFound
	if _, err := c.SecurityLookup(context.Background(), in); !errors.Is(err, ErrSecurityRelayNotSupported) {
		t.Errorf("404: %v", err)
	}
	status = http.StatusUnauthorized
	if _, err := c.SecurityLookup(context.Background(), in); !errors.Is(err, ErrAuthFailed) {
		t.Errorf("401: %v", err)
	}
}

// TestSecurityLookupRecordsThePerNodeBudget (SECP-26, lane LEFT-SHARED): the
// relay's per-node budget header is recorded from a 200 and a 429; an answer
// without it (an older server) or with a value out of range keeps the last.
func TestSecurityLookupRecordsThePerNodeBudget(t *testing.T) {
	securityRelayPerMinute.Store(0)
	defer securityRelayPerMinute.Store(0)
	header, status := "", http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if header != "" {
			w.Header().Set(orgcontract.SecurityLookupPerMinuteHeader, header)
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		writeTestJSON(w, http.StatusOK, orgcontract.SecurityLookupResponse{Mode: "relay"})
	}))
	defer srv.Close()
	c, _, _ := enrolledClient(t, srv.URL)
	in := orgcontract.SecurityLookupRequest{Queries: []orgcontract.SecurityLookupQuery{{Ecosystem: "npm", Name: "left-pad"}}}
	if _, err := c.SecurityLookup(context.Background(), in); err != nil || SecurityRelayPerMinute() != 0 {
		t.Fatalf("an older server sends no budget: %d (%v)", SecurityRelayPerMinute(), err)
	}
	header = "20"
	if _, err := c.SecurityLookup(context.Background(), in); err != nil || SecurityRelayPerMinute() != 20 {
		t.Fatalf("a 200 with the budget: %d (%v)", SecurityRelayPerMinute(), err)
	}
	header, status = "10", http.StatusTooManyRequests
	if _, err := c.SecurityLookup(context.Background(), in); !errors.Is(err, ErrSecurityRelayRateLimited) || SecurityRelayPerMinute() != 10 {
		t.Fatalf("a 429 with the budget: %d (%v)", SecurityRelayPerMinute(), err)
	}
	header, status = "-4", http.StatusOK
	if _, _ = c.SecurityLookup(context.Background(), in); SecurityRelayPerMinute() != 10 {
		t.Fatalf("a malformed budget must keep the last: %d", SecurityRelayPerMinute())
	}
}
