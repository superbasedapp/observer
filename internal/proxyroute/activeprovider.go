package proxyroute

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// activeprovider.go: the active-provider post-pass (surface-gap review CLI-3,
// lane w4-layers). A route inspector reads the base URL Observer's writer
// writes, but a tool with several providers talks only to the one its config
// selects. When the selected provider is not the one the route was written
// for, the route is in the file and never used: the inspector says "ours",
// the turns go straight to the vendor, and the OTLP token owner, the doctor
// and route maintenance would all believe the proxy sees them.
//
// ApplyActiveProvider turns such a row into RouteInactiveProvider. It is a
// post-pass over InspectRoutes (the inspection table is not changed), applied
// only by callers that read "is this tool's traffic proxied": the OTLP token
// owner, the doctor row, route maintenance and, since decision DEC-7 (lane
// w4-wire), the managed-integrity probe, where the state has its own
// routeVerdictRules row and reaches the org as the closed
// `inactive_provider_tools` labels (InactiveProviderTools), never as drift.
//
// Report only. Every read is member-only: a struct with the selector keys
// alone, so no credential value in the same file is decoded.

// RouteInactiveProvider: the route Observer wrote is in the file, but the
// tool's active provider is another one, so its turns do not reach the
// proxy. Derived from RouteOurs by ApplyActiveProvider; never returned by
// InspectRoutes itself.
const RouteInactiveProvider RouteState = "inactive_provider"

// activeProviderReader reads one tool's config file and reports whether its
// active provider is NOT the one the route covers (true: inactive). ok false
// when the file cannot be read or names no provider: the row is left alone.
type activeProviderReader func(path string) (inactive, ok bool)

// activeProviderReaders is the per-tool side table beside routeInspectors
// (the inspection table keys by tool too). One test case per row
// (TestApplyActiveProvider).
var activeProviderReaders = map[string]activeProviderReader{
	// crush: models.large.provider selects the provider; the route is
	// written under providers.openai.
	"crush": familyProviderReader("crush/models.large.provider", "crush/user-json", decodeCrushProvider),
	// qwen-code: security.auth.selectedType selects the auth type; the route
	// (model.baseUrl) applies to type openai. qwen-oauth is unverified (live
	// check 21) and stays "ours".
	"qwen-code": familyProviderReader("qwen-code/security.auth.selectedType", "qwen-code/user-settings", decodeQwenAuthType),
	// kimi-code: default_model -> models.<alias>.provider -> providers.<name>.type.
	// readKimiCodeBaseURL already reads the active provider when its type is
	// openai, so a row that read "ours" from the fallback providers.openai
	// table while another type is active is inactive.
	"kimi-code": readKimiActiveProvider,
}

// ApplyActiveProvider returns statuses with every RouteOurs row whose tool's
// active provider is not the routed one turned into RouteInactiveProvider.
// The slice is copied; statuses is not modified.
func ApplyActiveProvider(statuses []RouteStatus) []RouteStatus {
	out := make([]RouteStatus, len(statuses))
	copy(out, statuses)
	for i, s := range out {
		if s.State != RouteOurs || s.ConfigPath == "" {
			continue
		}
		read := activeProviderReaders[s.Tool]
		if read == nil {
			continue
		}
		if inactive, ok := read(s.ConfigPath); ok && inactive {
			out[i].State = RouteInactiveProvider
		}
	}
	return out
}

// familyProviderReader reads the selector with decode and classifies it
// through the agentconfig family (the one owner of the provider classes): an
// inactive_provider finding means the active provider is another one.
func familyProviderReader(familyID, fileID string, decode func([]byte) (map[string]any, bool)) activeProviderReader {
	return func(path string) (bool, bool) {
		fam, ok := agentconfig.FamilyByID(familyID)
		if !ok {
			return false, false
		}
		var row agentconfig.FileRow
		for _, r := range agentconfig.Files() {
			if r.ID == fileID {
				row = r
				break
			}
		}
		if row.ID == "" {
			return false, false
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return false, false
		}
		tree, ok := decode(raw)
		if !ok {
			return false, false
		}
		fs, err := agentconfig.EvaluateLayers(agentconfig.LayerInput{
			Files:    []agentconfig.LayerFile{{Row: row, Tree: tree}},
			Families: []agentconfig.Family{fam},
		})
		if err != nil {
			return false, false
		}
		for _, f := range fs {
			if f.Code == agentconfig.FindingInactiveProvider {
				return true, true
			}
		}
		return false, true
	}
}

// decodeCrushProvider reads models.large.provider alone from crush.json.
func decodeCrushProvider(raw []byte) (map[string]any, bool) {
	var doc struct {
		Models struct {
			Large struct {
				Provider string `json:"provider"`
			} `json:"large"`
		} `json:"models"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || strings.TrimSpace(doc.Models.Large.Provider) == "" {
		return nil, false
	}
	return map[string]any{"models": map[string]any{"large": map[string]any{"provider": doc.Models.Large.Provider}}}, true
}

// decodeQwenAuthType reads security.auth.selectedType alone from Qwen
// Code's settings.json.
func decodeQwenAuthType(raw []byte) (map[string]any, bool) {
	var doc struct {
		Security struct {
			Auth struct {
				SelectedType string `json:"selectedType"`
			} `json:"auth"`
		} `json:"security"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || strings.TrimSpace(doc.Security.Auth.SelectedType) == "" {
		return nil, false
	}
	return map[string]any{"security": map[string]any{"auth": map[string]any{"selectedType": doc.Security.Auth.SelectedType}}}, true
}

// readKimiActiveProvider resolves Kimi Code's active provider type from
// config.toml, member-only (api_key and every other provider field are not
// decoded).
func readKimiActiveProvider(path string) (bool, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, false
	}
	var doc struct {
		DefaultModel string `toml:"default_model"`
		Models       map[string]struct {
			Provider string `toml:"provider"`
		} `toml:"models"`
		Providers map[string]struct {
			Type string `toml:"type"`
		} `toml:"providers"`
	}
	if _, err := toml.Decode(string(raw), &doc); err != nil {
		return false, false
	}
	alias := strings.TrimSpace(doc.DefaultModel)
	if alias == "" {
		return false, false
	}
	name := strings.TrimSpace(doc.Models[alias].Provider)
	if name == "" {
		return false, false
	}
	p, ok := doc.Providers[name]
	if !ok {
		return false, false
	}
	return strings.TrimSpace(p.Type) != "openai", true
}
