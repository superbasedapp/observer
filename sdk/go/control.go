package superbased

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	apiVersionHeader = "X-SBO-SDK-API-Version"
	apiVersion       = "1"
)

// controlPaths: resource -> (machine path, gateway path). {name}, {id} and
// {version} are filled by the caller (URL-escaped).
var controlPaths = map[string][2]string{
	"scores":             {"/api/obs/scores", "/v1/sdk/scores"},
	"prompt":             {"/api/obs/sdk/prompts/{name}", "/v1/sdk/prompts/{name}"},
	"prompts":            {"/api/obs/sdk/prompts", "/v1/sdk/prompts"},
	"datasets":           {"/api/obs/eval/datasets", "/v1/sdk/datasets"},
	"dataset":            {"/api/obs/eval/datasets/{id}", "/v1/sdk/datasets/{id}"},
	"dataset_items":      {"/api/obs/eval/datasets/{id}/items", "/v1/sdk/datasets/{id}/snapshots/{version}/items"},
	"dataset_snapshot":   {"/api/obs/eval/datasets/{id}/items", "/v1/sdk/datasets/{id}/snapshots"},
	"experiments":        {"/api/obs/eval/experiments", "/v1/sdk/experiments"},
	"experiment":         {"/api/obs/eval/experiments/{id}", "/v1/sdk/experiments/{id}"},
	"experiment_results": {"/api/obs/eval/experiments/{id}/results", "/v1/sdk/experiments/{id}/results"},
	"experiment_finish":  {"/api/obs/eval/experiments/{id}/finish", "/v1/sdk/experiments/{id}/finish"},
	"trace_cost":         {"/api/obs/trace/{id}", "/v1/sdk/traces/{id}/cost"},
}

// side is one destination's control API.
type side struct {
	name    string // "local" or "online"
	base    string
	headers map[string]string // the online one carries the credential
	timeout time.Duration
}

func (s side) url(resource string, query []queryParam, parts map[string]string) string {
	p := controlPaths[resource][0]
	if s.name == DestinationOnline {
		p = controlPaths[resource][1]
	}
	for k, v := range parts {
		p = strings.ReplaceAll(p, "{"+k+"}", url.PathEscape(v))
	}
	return joinURL(s.base, p, query)
}

func (s side) call(ctx context.Context, method, resource string, body any, query []queryParam, headers map[string]string, parts map[string]string) *response {
	h := map[string]string{}
	for k, v := range s.headers {
		h[k] = v
	}
	for k, v := range headers {
		h[k] = v
	}
	return doRequest(ctx, method, s.url(resource, query, parts), body, h, s.timeout)
}

var (
	fallbackMu   sync.Mutex
	fallbackPlan *plan
)

// currentPlan is the plan of the last Init, or one resolved from the
// environment (cached) when the app calls a control function before Init.
func currentPlan() *plan {
	if p := activePlan(); p != nil {
		return p
	}
	fallbackMu.Lock()
	defer fallbackMu.Unlock()
	if fallbackPlan == nil {
		s, err := resolveSettings(osEnv, Options{})
		if err != nil {
			s, _ = resolveSettings(osEnv, Options{SampleRate: Float(1)})
		}
		fallbackPlan = resolvePlan(s, osEnv, explicitInputs{})
	}
	return fallbackPlan
}

func apiTimeout() time.Duration {
	if s := CurrentSettings(); s != nil {
		return s.APITimeout
	}
	return DefaultAPITimeout
}

// sides is the control API of each active destination, online first. A
// degraded online (no gateway or no credential) has no target (review R-B18):
// callers report unavailableReason. Only Admit may fall back to the machine.
func sides(p *plan) []side {
	if p == nil {
		p = currentPlan()
	}
	t := apiTimeout()
	var out []side
	if p.onlineEnabled() {
		h := p.onlineHeaders()
		h[apiVersionHeader] = apiVersion
		out = append(out, side{DestinationOnline, p.gatewayURL, h, t})
	}
	if p.destination == DestinationLocal || p.destination == DestinationBoth {
		out = append(out, side{DestinationLocal, p.nodeURL, map[string]string{}, t})
	}
	return out
}

func unavailableReason(p *plan) string {
	if p == nil {
		p = currentPlan()
	}
	if p.degraded != "" {
		return p.degraded
	}
	return "destination " + p.destination + " has no usable target"
}
