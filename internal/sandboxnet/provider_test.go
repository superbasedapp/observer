package sandboxnet

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestGateway_ProviderBlock pins the three refusals of section 7.3 and
// that an ordinary destination still works with the block on, through the
// real CONNECT path.
func TestGateway_ProviderBlock(t *testing.T) {
	t.Parallel()
	anth := net.ParseIP("198.51.100.10")
	for _, tc := range []struct {
		name       string
		target     string
		block      bool
		wantStatus int
		wantRule   string
	}{
		{"provider host refused", "api.anthropic.com:443", true, http.StatusForbidden, RuleModelProviderHost},
		{"provider subdomain refused", "eu.api.anthropic.com:443", true, http.StatusForbidden, RuleModelProviderHost},
		{"configured upstream refused", "llm.corp.example:443", true, http.StatusForbidden, RuleModelProviderHost},
		{"literal IP refused", "203.0.113.7:443", true, http.StatusForbidden, RuleLiteralIP},
		{"literal provider IP refused", "198.51.100.10:443", true, http.StatusForbidden, RuleLiteralIP},
		{"literal loopback still names its own rule", "127.0.0.1:443", true, http.StatusForbidden, RuleLoopback},
		{"name resolving to a provider address refused", "relay.example:443", true, http.StatusForbidden, RuleModelProviderAddress},
		{"ordinary host allowed", "example.test:443", true, http.StatusOK, ""},
		{"provider host allowed with the block off", "api.anthropic.com:443", false, http.StatusOK, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			echo := startTCPServer(t, echoHandler)
			f := &fakeNet{
				resolve: map[string][]net.IP{
					"api.anthropic.com":    {anth},
					"eu.api.anthropic.com": {anth},
					"relay.example":        {anth},
					"example.test":         {testPublicIP},
				},
				routes: map[string]string{"203.0.113.7:443": echo, "198.51.100.10:443": echo},
			}
			g := f.gateway()
			var b *ProviderBlock
			if tc.block {
				b = NewProviderBlock([]string{"llm.corp.example"})
				g.Providers = b
			}
			path := startGateway(t, g)
			resp, c, _ := rawRequest(t, path, http.MethodConnect, connectHead(tc.target), "")
			defer func() { _ = c.Close() }()
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if tc.wantRule == "" {
				return
			}
			body, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(body), tc.wantRule) {
				t.Fatalf("body %q lacks rule %s", body, tc.wantRule)
			}
			if tc.wantRule == RuleLoopback {
				return
			}
			if !strings.Contains(string(body), "Observer proxy") {
				t.Fatalf("body %q lacks the proxy hint", body)
			}
			if b.Refused() != 1 {
				t.Fatalf("refusals counted %d, want 1", b.Refused())
			}
			for _, d := range f.dials() {
				t.Fatalf("a refused request dialled %s", d)
			}
		})
	}
}

// TestGateway_ProviderBlockAbsoluteForm: the same block applies to an
// absolute-form http request.
func TestGateway_ProviderBlockAbsoluteForm(t *testing.T) {
	t.Parallel()
	f := &fakeNet{resolve: map[string][]net.IP{"api.openai.com": {testPublicIP}}}
	g := f.gateway()
	g.Providers = NewProviderBlock(nil)
	path := startGateway(t, g)
	head := "GET http://api.openai.com/v1/models HTTP/1.1\r\nHost: api.openai.com\r\n\r\n"
	resp, c, _ := rawRequest(t, path, http.MethodGet, head, "")
	defer func() { _ = c.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), RuleModelProviderHost) {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
}

func TestNilProviderBlockIsOff(t *testing.T) {
	var b *ProviderBlock
	if b.checkTarget("api.anthropic.com") != "" || b.Refused() != 0 {
		t.Fatal("a nil block refused")
	}
}

// TestGateway_ProviderBlockKeepsTheAllowList: a literal IP inside the
// operator's private allow-list is still dialled with the block on.
func TestGateway_ProviderBlockKeepsTheAllowList(t *testing.T) {
	t.Parallel()
	echo := startTCPServer(t, echoHandler)
	allow, err := ParseAllowCIDRs([]string{"10.20.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeNet{routes: map[string]string{"10.20.0.5:5432": echo}, allow: allow}
	g := f.gateway()
	g.Providers = NewProviderBlock(nil)
	path := startGateway(t, g)
	resp, c, _ := rawRequest(t, path, http.MethodConnect, connectHead("10.20.0.5:5432"), "")
	defer func() { _ = c.Close() }()
	if resp.StatusCode != http.StatusOK || g.Providers.Refused() != 0 {
		t.Fatalf("status %d refused %d", resp.StatusCode, g.Providers.Refused())
	}
}

// TestGateway_ProviderBlockSharedFrontEnds pins audit finding P-006 (1): a
// name that shares a front-end address with a provider host on Google's or
// Cloudflare's shared edge is not refused, so go and npm traffic passes,
// while a name resolving to Anthropic's own address block still is.
func TestGateway_ProviderBlockSharedFrontEnds(t *testing.T) {
	t.Parallel()
	google := net.ParseIP("198.51.100.20")
	cloudflare := net.ParseIP("198.51.100.30")
	anth := net.ParseIP("198.51.100.10")
	for _, tc := range []struct {
		target     string
		wantStatus int
	}{
		{"proxy.golang.org:443", http.StatusOK},
		{"storage.googleapis.com:443", http.StatusOK},
		{"oauth2.googleapis.com:443", http.StatusOK},
		{"registry.npmjs.org:443", http.StatusOK},
		{"relay.example:443", http.StatusForbidden},
	} {
		t.Run(tc.target, func(t *testing.T) {
			t.Parallel()
			echo := startTCPServer(t, echoHandler)
			f := &fakeNet{
				resolve: map[string][]net.IP{
					"api.anthropic.com":                 {anth},
					"generativelanguage.googleapis.com": {google},
					"chatgpt.com":                       {cloudflare},
					"openrouter.ai":                     {cloudflare},
					"proxy.golang.org":                  {google},
					"storage.googleapis.com":            {google},
					"oauth2.googleapis.com":             {google},
					"registry.npmjs.org":                {cloudflare},
					"relay.example":                     {anth},
				},
				routes: map[string]string{"198.51.100.20:443": echo, "198.51.100.30:443": echo, "198.51.100.10:443": echo},
			}
			g := f.gateway()
			g.Providers = NewProviderBlock(nil)
			path := startGateway(t, g)
			resp, c, _ := rawRequest(t, path, http.MethodConnect, connectHead(tc.target), "")
			defer func() { _ = c.Close() }()
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			for _, h := range f.resolves() {
				if h == "generativelanguage.googleapis.com" || h == "chatgpt.com" || h == "openrouter.ai" {
					t.Fatalf("a shared front-end provider host %s was resolved into the address set", h)
				}
			}
		})
	}
}

// TestProviderBlockRefreshOwnContextAndIncomplete pins the refresh
// discipline: the lookups run on the block's own context (a cancelled
// request context does not cut them short), and a refresh cut off by its
// timeout never marks the set ready, so the next request tries again, and
// a request whose wait ends on such a refresh is refused, never judged
// against the partial set (P-026, lane sbx-p2b).
func TestProviderBlockRefreshOwnContextAndIncomplete(t *testing.T) {
	t.Parallel()
	anth := net.ParseIP("198.51.100.10")
	b := NewProviderBlock(nil)
	b.resolveTimeout = 50 * time.Millisecond

	hang := true
	var mu sync.Mutex
	resolve := func(ctx context.Context, host string) ([]net.IP, error) {
		mu.Lock()
		h := hang
		mu.Unlock()
		if h {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		if host == "api.anthropic.com" {
			return []net.IP{anth}, nil
		}
		return nil, errors.New("no such host")
	}
	unrelated := net.ParseIP("203.0.113.7")
	for _, ip := range []net.IP{anth, unrelated} {
		if rule := b.checkResolved([]net.IP{ip}, resolve); rule != RuleProviderAddressesUnknown {
			t.Fatalf("%s after an incomplete refresh: rule %q, want %s", ip, rule, RuleProviderAddressesUnknown)
		}
	}
	b.mu.Lock()
	ready := b.ready
	b.mu.Unlock()
	if ready {
		t.Fatal("a refresh cut off by its timeout marked the set ready")
	}
	mu.Lock()
	hang = false
	mu.Unlock()
	if rule := b.checkResolved([]net.IP{anth}, resolve); rule != RuleModelProviderAddress {
		t.Fatalf("rule %q after a complete refresh, want %s", rule, RuleModelProviderAddress)
	}
	if rule := b.checkResolved([]net.IP{unrelated}, resolve); rule != "" {
		t.Fatalf("an unrelated address after a complete refresh: rule %q", rule)
	}
	b.mu.Lock()
	ready = b.ready
	b.mu.Unlock()
	if !ready {
		t.Fatal("a complete refresh did not mark the set ready")
	}

	// The gateway passes a cancelled request context; the block's lookups
	// still complete because they never use it.
	b2 := NewProviderBlock(nil)
	f := &fakeNet{resolve: map[string][]net.IP{"api.anthropic.com": {anth}, "relay.example": {anth}}}
	g := f.gateway()
	g.Providers = b2
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	g.Resolve = func(rctx context.Context, host string) ([]net.IP, error) {
		if host == "relay.example" {
			return []net.IP{anth}, nil
		}
		if rctx.Err() != nil {
			return nil, rctx.Err()
		}
		return []net.IP{anth}, nil
	}
	if _, err := g.dialChecked(ctx, "tcp", "relay.example:443", formConnect); err == nil || !strings.Contains(err.Error(), RuleModelProviderAddress) {
		t.Fatalf("err %v, want a %s refusal despite the cancelled request context", err, RuleModelProviderAddress)
	}
}

// TestProviderBlockNoFailOpenWindow (P-017 (e)): a request that arrives
// while the first refresh is in flight waits for it and is refused, never
// passed against an empty set; and a refusal answers without running a
// lookup on its own path (the follow-up refresh runs in the background).
func TestProviderBlockNoFailOpenWindow(t *testing.T) {
	t.Parallel()
	anth := net.ParseIP("198.51.100.10")
	b := NewProviderBlock(nil)
	gate := make(chan struct{})
	var calls sync.WaitGroup
	var mu sync.Mutex
	slow := true
	resolve := func(ctx context.Context, host string) ([]net.IP, error) {
		mu.Lock()
		s := slow
		mu.Unlock()
		if s {
			select {
			case <-gate:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if host == "api.anthropic.com" {
			return []net.IP{anth}, nil
		}
		return nil, errors.New("no such host")
	}
	results := make(chan string, 2)
	for i := 0; i < 2; i++ {
		calls.Add(1)
		go func() {
			defer calls.Done()
			results <- b.checkResolved([]net.IP{anth}, resolve)
		}()
	}
	time.Sleep(50 * time.Millisecond)
	select {
	case r := <-results:
		t.Fatalf("a request answered %q before the first refresh finished", r)
	default:
	}
	close(gate)
	calls.Wait()
	close(results)
	for r := range results {
		if r != RuleModelProviderAddress {
			t.Fatalf("a request during the first refresh answered %q", r)
		}
	}
	// With the set ready and every later lookup hanging until its timeout,
	// a refusal still answers at once.
	mu.Lock()
	slow = true
	mu.Unlock()
	b.resolveTimeout = 5 * time.Second
	hang := make(chan struct{})
	defer close(hang)
	hangResolve := func(ctx context.Context, _ string) ([]net.IP, error) {
		select {
		case <-hang:
		case <-ctx.Done():
		}
		return nil, errors.New("cut")
	}
	start := time.Now()
	if r := b.checkResolved([]net.IP{anth}, hangResolve); r != RuleModelProviderAddress {
		t.Fatalf("rule %q", r)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("a refusal ran a lookup on its own path (%s)", d)
	}
}

// TestProviderBlockPartialFirstRefreshFailsClosed (P-026, lane sbx-p2b): the
// first refresh resolves one provider host and then hangs until its
// timeout; a provider address it never reached must not pass, and once a
// complete set exists a later timed-out refresh keeps it.
func TestProviderBlockPartialFirstRefreshFailsClosed(t *testing.T) {
	t.Parallel()
	b := NewProviderBlock(nil)
	b.addrHosts = []string{"a.provider.example", "b.provider.example"}
	b.resolveTimeout = 50 * time.Millisecond
	first, second := b.addrHosts[0], b.addrHosts[1]
	firstIP, secondIP := net.ParseIP("198.51.100.20"), net.ParseIP("198.51.100.21")
	var mu sync.Mutex
	hang := true
	resolve := func(ctx context.Context, host string) ([]net.IP, error) {
		switch host {
		case first:
			return []net.IP{firstIP}, nil
		case second:
			mu.Lock()
			h := hang
			mu.Unlock()
			if h {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return []net.IP{secondIP}, nil
		}
		return nil, errors.New("no such host")
	}
	if rule := b.checkResolved([]net.IP{secondIP}, resolve); rule != RuleProviderAddressesUnknown {
		t.Fatalf("an address the cut-off refresh never reached: rule %q", rule)
	}
	mu.Lock()
	hang = false
	mu.Unlock()
	if rule := b.checkResolved([]net.IP{secondIP}, resolve); rule != RuleModelProviderAddress {
		t.Fatalf("after a complete refresh: rule %q", rule)
	}
	mu.Lock()
	hang = true
	mu.Unlock()
	<-b.startRefresh(resolve) // a later refresh that times out
	if rule := b.checkResolved([]net.IP{secondIP}, resolve); rule != RuleModelProviderAddress {
		t.Fatalf("a timed-out later refresh dropped the complete set: rule %q", rule)
	}
}
