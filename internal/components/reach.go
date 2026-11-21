package components

// reach.go is the Reach value of every catalog row (plan 06 18.3.3): which
// deployment shapes the component can reach and how far it is on by default
// in a pooled SaaS host. It is data, set in the row (or grandfathered below),
// never inferred from a stage at resolve time: keying the default on
// Stability alone would have switched off modules that are on today.

// Reach is a bit set over the deployment shapes a component reaches.
type Reach uint8

// Reach bits.
const (
	// ReachSingle: the component can run in a single-tenant self-hosted
	// deployment (the [components] block is the ceiling there).
	ReachSingle Reach = 1 << iota
	// ReachDedicated: it can run in a dedicated deployment.
	ReachDedicated
	// ReachPooled: it is ON by default in pooled SaaS, subject to
	// entitlement. Implies ReachPooledOffer.
	ReachPooled
	// ReachPooledOffer: the operator may open it in pooled SaaS through the
	// availability envelope (named orgs, or a cohort). A row without this
	// bit can never be widened into pooled by an envelope.
	ReachPooledOffer
)

const reachKnown = ReachSingle | ReachDedicated | ReachPooled | ReachPooledOffer

// Has reports whether every bit of b is set.
func (r Reach) Has(b Reach) bool { return r&b == b }

// Valid reports whether r is a usable reach: non-zero, only known bits,
// reaching both private shapes (the private default is "as compiled and
// selected", 18.3.2), and ReachPooled implying ReachPooledOffer.
func (r Reach) Valid() bool {
	if r == 0 || r&^reachKnown != 0 || !r.Has(ReachSingle|ReachDedicated) {
		return false
	}
	return !r.Has(ReachPooled) || r.Has(ReachPooledOffer)
}

// String names the set bits, "none" for zero.
func (r Reach) String() string {
	if r == 0 {
		return "none"
	}
	names := []struct {
		bit  Reach
		name string
	}{{ReachSingle, "single"}, {ReachDedicated, "dedicated"}, {ReachPooled, "pooled"}, {ReachPooledOffer, "pooled-offer"}}
	out := ""
	for _, n := range names {
		if r.Has(n.bit) {
			if out != "" {
				out += "|"
			}
			out += n.name
		}
	}
	return out
}

// reachByStage is the stage table for a NEW row (18.3.3): the default reach
// of a component that is not grandfathered. A new row sets
// `Reach: ReachOf(Stability...)` explicitly; a row with no Reach fails
// TestEveryRowHasReach.
var reachByStage = map[Stability]Reach{
	// Off in pooled, named orgs only (D-31): offerable, never on by default.
	StabilityExperimental: ReachSingle | ReachDedicated | ReachPooledOffer,
	// Off but offerable to a cohort.
	StabilityPreview: ReachSingle | ReachDedicated | ReachPooledOffer,
	// On, subject to entitlement.
	StabilityStable: ReachSingle | ReachDedicated | ReachPooled | ReachPooledOffer,
	// Kept for orgs using it, never newly enabled by default.
	StabilityDeprecated: ReachSingle | ReachDedicated | ReachPooledOffer,
}

// ReachOf returns the stage default reach for a new row (zero for an unknown
// stage, which the pin test rejects).
func ReachOf(s Stability) Reach { return reachByStage[s] }

// grandfatheredReach is the reach of a row that existed at catalog version 4
// (18.3.3: its Reach equals what the image does today). Rows with an image
// column: in the full image by default -> on in pooled; off -> offerable;
// per-deploy / separate / out -> private shapes only (pooled hosts do not
// choose storage backends or run separate images). Node, adapter and core
// rows reach every shape: nodes resolve through the node.components policy
// the org runtime signs.
func grandfatheredReach(c Component) Reach {
	all := ReachSingle | ReachDedicated | ReachPooled | ReachPooledOffer
	if c.Images == nil {
		return all
	}
	switch c.Images[ImageFull] {
	case ImageIn:
		return all
	case ImageOff:
		return ReachSingle | ReachDedicated | ReachPooledOffer
	}
	return ReachSingle | ReachDedicated
}

// grandfathered lists the ids that existed at catalog version 4 and take
// grandfatheredReach when their row sets none. A row added later is not here.
var grandfathered = map[string]bool{
	"adapter.aider":                      true,
	"adapter.antigravity":                true,
	"adapter.antigravity-cli":            true,
	"adapter.autohand":                   true,
	"adapter.chatgpt-web":                true,
	"adapter.claude-code":                true,
	"adapter.claude-web":                 true,
	"adapter.cline":                      true,
	"adapter.cline-cli":                  true,
	"adapter.codebuddy":                  true,
	"adapter.codex":                      true,
	"adapter.command-code":               true,
	"adapter.copilot":                    true,
	"adapter.copilot-cli":                true,
	"adapter.copilot-web":                true,
	"adapter.cortex-code":                true,
	"adapter.cowork":                     true,
	"adapter.crush":                      true,
	"adapter.cursor":                     true,
	"adapter.custom-agent":               true,
	"adapter.deepagents-code":            true,
	"adapter.deepseek":                   true,
	"adapter.devin":                      true,
	"adapter.dimcode":                    true,
	"adapter.dirac":                      true,
	"adapter.droid":                      true,
	"adapter.freebuff":                   true,
	"adapter.gemini-cli":                 true,
	"adapter.gemini-web":                 true,
	"adapter.goose":                      true,
	"adapter.grok":                       true,
	"adapter.grokbot":                    true,
	"adapter.hermes":                     true,
	"adapter.ibm-bob":                    true,
	"adapter.junie":                      true,
	"adapter.kilo-code":                  true,
	"adapter.kilo-code-cli":              true,
	"adapter.kimchi":                     true,
	"adapter.kimi-code":                  true,
	"adapter.kiro-cli":                   true,
	"adapter.kiro-crew":                  true,
	"adapter.mistral-code":               true,
	"adapter.muse":                       true,
	"adapter.open-interpreter":           true,
	"adapter.openclaw":                   true,
	"adapter.opencode":                   true,
	"adapter.perplexity-web":             true,
	"adapter.pi":                         true,
	"adapter.poolside":                   true,
	"adapter.prime-agent":                true,
	"adapter.qoder":                      true,
	"adapter.qwen-code":                  true,
	"adapter.stakpak":                    true,
	"adapter.vtcode":                     true,
	"adapter.zcode":                      true,
	"adapter.zed":                        true,
	"agentaccess.relay":                  true,
	"analytics":                          true,
	"archive":                            true,
	"benchmark":                          true,
	"capture.browser":                    true,
	"capture.proxy":                      true,
	"cloud.intelligence":                 true,
	"codeintel":                          true,
	"compression.indexing":               true,
	"compression.shell":                  true,
	"core":                               true,
	"demo":                               true,
	"edge":                               true,
	"egress.aggregate-share":             true,
	"egress.pricing-feed":                true,
	"export.otel":                        true,
	"guard":                              true,
	"guard.cloud":                        true,
	"ingest.otlp":                        true,
	"integration.agent-config":           true,
	"integration.hooks":                  true,
	"integration.mcp-server":             true,
	"integration.proxy-route":            true,
	"integration.service":                true,
	"integration.shell-wrap":             true,
	"integration.statusline":             true,
	"intervention":                       true,
	"isolation":                          true,
	"isolation.seal":                     true,
	"judge.client":                       true,
	"notify.email":                       true,
	"obs":                                true,
	"org.agentaccess":                    true,
	"org.aigateway":                      true,
	"org.analytics.clickhouse":           true,
	"org.assistant":                      true,
	"org.client":                         true,
	"org.core":                           true,
	"org.deploy-planner":                 true,
	"org.digest":                         true,
	"org.email":                          true,
	"org.harness":                        true,
	"org.log.kafka":                      true,
	"org.managed-settings":               true,
	"org.oidc":                           true,
	"org.opamp":                          true,
	"org.openshell":                      true,
	"org.planea.gateway":                 true,
	"org.pollers.cc":                     true,
	"org.pollers.codex":                  true,
	"org.pollers.copilot":                true,
	"org.pollers.cortex":                 true,
	"org.pollers.cursor":                 true,
	"org.pollers.kimchi":                 true,
	"org.pollers.m365":                   true,
	"org.pricing-feed":                   true,
	"org.saml":                           true,
	"org.scim":                           true,
	"org.security":                       true,
	"org.security.ci":                    true,
	"org.security.githubapp":             true,
	"org.security.relay":                 true,
	"org.selfobs":                        true,
	"org.sor.azblob":                     true,
	"org.sor.s3":                         true,
	"org.update":                         true,
	"processobs":                         true,
	"projects":                           true,
	"projects.alignment-judge":           true,
	"proxy.compression":                  true,
	"proxy.routing":                      true,
	"remote":                             true,
	"security":                           true,
	"security.code":                      true,
	"security.dast":                      true,
	"security.deps":                      true,
	"security.feedback":                  true,
	"security.githooks":                  true,
	"security.provenance":                true,
	"security.reach.go":                  true,
	"security.scan.actionlint":           true,
	"security.scan.custom":               true,
	"security.scan.image.trivy":          true,
	"security.scan.kics":                 true,
	"security.scan.opengrep":             true,
	"security.scan.os":                   true,
	"security.scan.osv":                  true,
	"security.scan.sarif-import":         true,
	"security.scan.scalibr":              true,
	"security.scan.trivy":                true,
	"security.secrets":                   true,
	"security.trust":                     true,
	"terminals":                          true,
	"terminals.sandbox":                  true,
	"terminals.sandbox.apple-container":  true,
	"terminals.sandbox.credentials":      true,
	"terminals.sandbox.daytona":          true,
	"terminals.sandbox.docker":           true,
	"terminals.sandbox.e2b":              true,
	"terminals.sandbox.hcs":              true,
	"terminals.sandbox.instabox":         true,
	"terminals.sandbox.landlock":         true,
	"terminals.sandbox.modal":            true,
	"terminals.sandbox.mxc":              true,
	"terminals.sandbox.mxc.appcontainer": true,
	"terminals.sandbox.oci":              true,
	"terminals.sandbox.oci.readopt":      true,
	"terminals.sandbox.openshell":        true,
	"terminals.sandbox.openshell-org":    true,
	"terminals.sandbox.seatbelt":         true,
	"terminals.sandbox.vercel":           true,
	"terminals.sandbox.vm":               true,
	"terminals.sandbox.wslc":             true,
	"terminals.ssh":                      true,
	"ui.dashboard":                       true,
	"ui.export-xlsx":                     true,
}
