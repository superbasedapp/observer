package sandboxnet

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// provider.go is the model-provider host block (sandbox plan v2 section
// 7.3, ledger SBX-CAP-1): while a run's capture is full only because the
// gateway guards it (capture rule C6), the gateway refuses
//
//	(a) a CONNECT or absolute-form target whose host is a model-provider
//	    host or a subdomain of one,
//	(b) a name target that resolves to an address of a provider host that
//	    answers from the provider's own address block (only the rows marked
//	    sandboxvocab.ProviderHost.DedicatedAddresses; shared Google and
//	    Cloudflare front ends are left out so go and npm traffic passes;
//	    resolved on first use and refreshed on every refusal), and
//	(c) every literal-IP target, because a run that claims full capture has
//	    no need for one and the alternative is an unbounded address list.
//	    One exception, decided in lane sbx-p1a: a literal IP inside the
//	    operator's own private allow-list ([terminal.sandbox].
//	    egress_allow_cidrs) still passes, because the operator named that
//	    range explicitly (a database on a container network, say) and a
//	    model provider's public address can never be inside it. A literal
//	    private IP that is not allow-listed is still refused by its private
//	    rule first, so the refusal names the config key that lifts it.
//
// The refusal is a 403 naming the rule and the proxy; it is never a
// redirect (a TLS connection cannot be redirected without a CA in the box,
// and the launcher already points proxy-routed tools at the proxy, so a
// refused direct call means the agent bypassed its own configuration).

// The provider-block rule names (operator-visible in the 403 body).
const (
	RuleModelProviderHost    = "model-provider-host"
	RuleModelProviderAddress = "model-provider-address"
	RuleLiteralIP            = "literal-ip"
	// RuleProviderAddressesUnknown refuses a name target while the provider
	// address set has never been completely resolved (its refresh timed
	// out): the target cannot be told apart from a provider address, so it
	// is refused rather than judged against a partial set (plans decision
	// log P-026, lane sbx-p2b).
	RuleProviderAddressesUnknown = "model-provider-addresses-unresolved"
)

// providerHint ends every provider-block refusal.
const providerHint = " (this run claims full capture, so model API calls must go through the Observer proxy the tool is configured with)"

// defaultProviderResolveTimeout bounds one refresh of the provider address
// set. The refresh runs on its own context, never the request's, so a
// client that hangs up mid-lookup cannot cut the set short.
const defaultProviderResolveTimeout = 10 * time.Second

// ProviderBlock is the per-run block. Build it with NewProviderBlock; the
// zero value blocks nothing and a nil *ProviderBlock is off.
type ProviderBlock struct {
	hosts     []string
	addrHosts []string

	// resolveTimeout overrides defaultProviderResolveTimeout (tests).
	resolveTimeout time.Duration

	mu    sync.Mutex
	addrs map[string]bool
	ready bool
	// inflight is closed when the refresh in flight ends; nil when none.
	inflight chan struct{}

	refused atomic.Int64
}

// NewProviderBlock returns a block over the closed provider list plus the
// extra hosts (the proxy's configured upstreams). The extra hosts are
// refused by name only: Observer cannot know whether a configured upstream
// sits on a shared front end, so its addresses never join the address rule.
func NewProviderBlock(extra []string) *ProviderBlock {
	return &ProviderBlock{
		hosts:     append(sandboxvocab.ModelProviderHosts(), extra...),
		addrHosts: sandboxvocab.DedicatedAddressHosts(),
	}
}

// Refused is how many requests the block refused (counted on the run).
func (b *ProviderBlock) Refused() int64 {
	if b == nil {
		return 0
	}
	return b.refused.Load()
}

// checkTarget applies rule (a) to a name target before any resolution: it
// returns the refusing rule, or "". A literal IP is judged by checkLiteral
// after the address policy.
func (b *ProviderBlock) checkTarget(host string) string {
	if b == nil || parseLiteral(host) != nil {
		return ""
	}
	if sandboxvocab.MatchesHost(host, b.hosts) {
		b.refused.Add(1)
		return RuleModelProviderHost
	}
	return ""
}

// checkLiteral applies rule (c) to a literal-IP target the address policy
// already allowed: refused unless it lies inside the operator's allow-list.
func (b *ProviderBlock) checkLiteral(ip net.IP, allow []netip.Prefix) string {
	if b == nil {
		return ""
	}
	if a, ok := toAddr(ip); ok {
		for _, p := range allow {
			if p.Contains(a) {
				return ""
			}
		}
	}
	b.refused.Add(1)
	return RuleLiteralIP
}

// checkResolved applies rule (b) to a name's resolved addresses; resolve is
// the gateway's resolver. Only the dedicated-address provider hosts feed the
// address set (sandboxvocab.ProviderHost.DedicatedAddresses), so a shared
// front end never refuses an unrelated name.
//
// Lane sbx-p2 (decision log P-017 (e)): until the set is ready, every
// request WAITS for the refresh in flight (bounded by the block's resolve
// timeout) instead of judging against a half-built set, so there is no
// fail-open window while the first refresh runs. A refusal schedules a
// refresh in the background and answers at once, so a refused request never
// runs a lookup on its own path. A refresh that did not finish (a timeout)
// adds what it found but never marks the set ready, so the next request
// waits for another try.
//
// Lane sbx-p2b (P-026): a request whose wait ends with the set still not
// ready (the refresh it waited for timed out) is refused with
// RuleProviderAddressesUnknown, never judged against the partial set: a
// provider address the cut-off refresh did not reach would otherwise pass.
// Once a refresh has completed, a later one that times out keeps the
// complete set it replaces (plus what it found), so it is never partial.
func (b *ProviderBlock) checkResolved(ips []net.IP, resolve func(context.Context, string) ([]net.IP, error)) string {
	if b == nil || len(b.addrHosts) == 0 {
		return ""
	}
	b.mu.Lock()
	ready := b.ready
	b.mu.Unlock()
	if !ready {
		<-b.startRefresh(resolve)
		b.mu.Lock()
		ready = b.ready
		b.mu.Unlock()
		if !ready {
			b.refused.Add(1)
			return RuleProviderAddressesUnknown
		}
	}
	b.mu.Lock()
	hit := false
	for _, ip := range ips {
		if b.addrs[normalize(ip).String()] {
			hit = true
			break
		}
	}
	b.mu.Unlock()
	if !hit {
		return ""
	}
	b.startRefresh(resolve)
	b.refused.Add(1)
	return RuleModelProviderAddress
}

// startRefresh starts a refresh unless one is in flight and returns a
// channel closed when the refresh in flight (this one or the earlier one)
// ends.
func (b *ProviderBlock) startRefresh(resolve func(context.Context, string) ([]net.IP, error)) <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.inflight != nil {
		return b.inflight
	}
	done := make(chan struct{})
	b.inflight = done
	timeout := b.resolveTimeout
	if timeout <= 0 {
		timeout = defaultProviderResolveTimeout
	}
	go b.refresh(resolve, timeout, done)
	return done
}

// refresh resolves every dedicated-address provider host outside the lock,
// then publishes the set and closes done. A host that does not resolve is
// skipped (it cannot be reached through the gateway either); a lookup cut
// off by the timeout makes the refresh incomplete.
func (b *ProviderBlock) refresh(resolve func(context.Context, string) ([]net.IP, error), timeout time.Duration, done chan struct{}) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	found := map[string]bool{}
	complete := true
	for _, h := range b.addrHosts {
		ips, err := resolve(ctx, h)
		if ctx.Err() != nil {
			complete = false
			break
		}
		if err != nil {
			continue
		}
		for _, ip := range ips {
			found[normalize(ip).String()] = true
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	defer close(done)
	b.inflight = nil
	if complete {
		b.addrs = found
		b.ready = true
		return
	}
	if b.addrs == nil {
		b.addrs = map[string]bool{}
	}
	for a := range found {
		b.addrs[a] = true
	}
}
