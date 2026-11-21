package cloudclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudpop"
)

// TestLearnSkew pins the skew rules: a believable Date header off by at
// least skewAdopt is adopted (either direction), a smaller difference resets
// to zero, and a missing, unparseable or absurd header changes nothing.
func TestLearnSkew(t *testing.T) {
	local := time.Unix(1_800_000_000, 0).UTC()
	for _, tc := range []struct {
		name  string
		start time.Duration
		date  string
		want  time.Duration
	}{
		{"server ten minutes ahead", 0, local.Add(10 * time.Minute).Format(http.TimeFormat), 10 * time.Minute},
		{"server three minutes behind", 0, local.Add(-3 * time.Minute).Format(http.TimeFormat), -3 * time.Minute},
		{"within the adopt band resets", 2 * time.Minute, local.Add(2 * time.Second).Format(http.TimeFormat), 0},
		{"no header keeps", 4 * time.Minute, "", 4 * time.Minute},
		{"garbage keeps", 4 * time.Minute, "yesterday-ish", 4 * time.Minute},
		{"absurd keeps", 4 * time.Minute, local.Add(30 * 24 * time.Hour).Format(http.TimeFormat), 4 * time.Minute},
	} {
		c := &Client{clock: func() time.Time { return local }}
		c.skew.Store(int64(tc.start))
		c.learnSkew(tc.date, local)
		if got := c.ClockSkew(); got != tc.want {
			t.Errorf("%s: skew %v, want %v", tc.name, got, tc.want)
		}
		if got, want := c.proofTime(), local.Add(tc.want); !got.Equal(want) {
			t.Errorf("%s: proofTime %v, want %v", tc.name, got, want)
		}
	}
}

// TestConnectPollSignsOnTheServerClock is L-142's guard: a machine whose
// clock is ten minutes behind the server had every connect poll refused
// ("proof-of-possession failed"). The refused response's Date header teaches
// the client the server's time, and the poll is re-sent once on it and
// accepted. A server that refuses whatever the clock still fails, as a proof
// refusal the caller can name.
func TestConnectPollSignsOnTheServerClock(t *testing.T) {
	serverNow := time.Unix(1_800_000_000, 0).Add(10 * time.Minute) // the test client's clock is 1_800_000_000
	for _, tc := range []struct {
		name         string
		alwaysRefuse bool
		wantCalls    int
		wantErr      bool
	}{
		{"refused once, accepted on the server clock", false, 2, false},
		{"refused whatever the clock", true, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c *Client
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Date", serverNow.UTC().Format(http.TimeFormat))
				_, err := cloudpop.Verify(r.Header.Get(headerPoP), cloudpop.VerifyParams{
					ExpectedMethod:          r.Method,
					ExpectedURL:             "http://" + r.Host + r.URL.Path,
					ExpectedThumbprint:      cloudpop.Thumbprint(c.DevicePublicKey()),
					ExpectedAccessTokenHash: cloudpop.HashAccessToken("req-skew"),
					Now:                     serverNow,
					MaxAge:                  time.Minute,
					MaxSkew:                 time.Minute,
				})
				if err != nil || tc.alwaysRefuse {
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte(`{"error":"proof-of-possession failed","code":"unauthorized"}`))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"status":"pending","target":null,"consent_receipt_id":""}`))
			}))
			t.Cleanup(srv.Close)
			c, _ = newTestClient(t, srv.URL, "")
			st, err := c.PollConnectRequest(context.Background(), "req-skew")
			if calls != tc.wantCalls {
				t.Fatalf("server saw %d requests, want %d", calls, tc.wantCalls)
			}
			if tc.wantErr {
				if !IsProofRejected(err) {
					t.Fatalf("err=%v, want a proof refusal", err)
				}
				return
			}
			if err != nil || st.Status != ConnectPending {
				t.Fatalf("poll = %+v, %v; want pending", st, err)
			}
			if got := c.ClockSkew(); got != 10*time.Minute {
				t.Fatalf("learned skew %v, want 10m", got)
			}
		})
	}
}
