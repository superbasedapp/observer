// Package customagent is the registered adapter identity for a developer's
// own agent (tool models.ToolCustomAgent, "custom-agent"; P-228).
//
// It parses nothing. An own agent has no on-disk transcript: its turns
// reach Observer only through the proxy, when the agent points its provider
// base URL at the node proxy and sends X-Superbased-Agent (internal/ownagent
// resolves the header, internal/proxy creates the capture session). The
// package exists so the tool id is declared in the three sources of truth
// (defaults.Adapters, the integration registry and the default
// EnabledAdapters list), exactly like the hook-only browser-chat rows, and
// so removing "custom-agent" from [observer.watch].enabled_adapters turns
// the header capture off.
package customagent
