package config

import (
	"fmt"
	"net/url"
	"strings"
)

// The SDK data destinations (D18). The contract is
// docs/plans/plane-a-sdk-buildout/contracts/destination.md.
const (
	// SDKDestinationLocal sends an app's data to this machine only.
	SDKDestinationLocal = "local"
	// SDKDestinationOnline sends it to the organization (or SaaS) gateway only.
	SDKDestinationOnline = "online"
	// SDKDestinationBoth sends it to both; the SDK exports to each itself.
	SDKDestinationBoth = "both"
)

// SDKDestinations is the closed set of explicit destination values, in
// display order. The empty string is also valid and means "the default".
var SDKDestinations = []string{SDKDestinationLocal, SDKDestinationOnline, SDKDestinationBoth}

// ObservabilitySDKConfig is [observability.sdk]: the machine's default for
// the superbased SDKs (D18). The SDKs read it over the loopback discovery
// route GET /api/sdk/destination; init() and SUPERBASED_DESTINATION win over
// it.
type ObservabilitySDKConfig struct {
	// Destination is where the SDKs send an app's data by default: local,
	// online or both. Empty (the default) means local when this machine is not
	// signed in for SDK data and both when it is (it holds an SDK key, from
	// `observer sdk sign-in`), or online when it is signed in but does not
	// receive app data itself (app observability off or not in this build).
	// Choosing online or both sends an app's
	// spans off this machine, so the dashboard asks for confirmation and an
	// agent's MCP request waits for your approval.
	Destination string `toml:"destination"`
	// GatewayURL overrides the organization gateway address the SDKs send
	// online data to (scheme, host and port, for example
	// https://gw.example.com:4318). Empty (the default) uses the address the
	// organization returned when this machine signed in.
	GatewayURL string `toml:"gateway_url"`
}

// validateObservabilitySDK checks [observability.sdk].
func validateObservabilitySDK(c ObservabilitySDKConfig) error {
	switch strings.TrimSpace(c.Destination) {
	case "", SDKDestinationLocal, SDKDestinationOnline, SDKDestinationBoth:
	default:
		return fmt.Errorf("config: observability.sdk.destination %q not in {local, online, both} (empty means the default)", c.Destination)
	}
	if g := strings.TrimSpace(c.GatewayURL); g != "" {
		if err := ValidateSDKGatewayURL(g); err != nil {
			return fmt.Errorf("config: observability.sdk.gateway_url: %w", err)
		}
	}
	return nil
}

// ValidateSDKGatewayURL checks a gateway base address: http or https, a host,
// and no path beyond "/", query, fragment or user info (the SDK appends
// /v1/traces itself, and a credential must never ride in a URL).
func ValidateSDKGatewayURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("not a URL: %w", err)
	}
	switch {
	case u.Scheme != "http" && u.Scheme != "https":
		return fmt.Errorf("%q must start with http:// or https://", raw)
	case u.Host == "" || u.Hostname() == "":
		return fmt.Errorf("%q has no host", raw)
	case u.User != nil:
		return fmt.Errorf("%q must not carry a user name or password", raw)
	case u.RawQuery != "" || u.Fragment != "":
		return fmt.Errorf("%q must not carry a query or fragment", raw)
	case u.Path != "" && u.Path != "/":
		return fmt.Errorf("%q must be a base address (scheme, host and port) without a path", raw)
	}
	return nil
}

// SDKDestinationResolution is the machine default after the D18 rule.
type SDKDestinationResolution struct {
	// Destination is local, online or both.
	Destination string
	// Source is "config", "default_signed_in", "default_signed_in_no_local"
	// or "default_not_signed_in".
	Source string
	// Configured is the raw setting ("" when unset).
	Configured string
}

// SDKSourceSignedInNoLocal is the resolution source of a signed-in machine
// that cannot receive app data itself (app observability off or not in the
// build): the default is online rather than both (review E-32, ruling D29).
const SDKSourceSignedInNoLocal = "default_signed_in_no_local"

// sdkDestinationRules is the D18 default table, walked top-down. localOn is
// whether this machine receives app data ([observability] on and compiled
// in).
var sdkDestinationRules = []struct {
	match       func(configured string, signedIn, localOn bool) bool
	destination func(configured string) string
	source      string
}{
	{
		match:       func(c string, _, _ bool) bool { return c != "" },
		destination: func(c string) string { return c },
		source:      "config",
	},
	{
		match:       func(_ string, signedIn, localOn bool) bool { return signedIn && localOn },
		destination: func(string) string { return SDKDestinationBoth },
		source:      "default_signed_in",
	},
	{
		match:       func(_ string, signedIn, _ bool) bool { return signedIn },
		destination: func(string) string { return SDKDestinationOnline },
		source:      SDKSourceSignedInNoLocal,
	},
	{
		match:       func(string, bool, bool) bool { return true },
		destination: func(string) string { return SDKDestinationLocal },
		source:      "default_not_signed_in",
	},
}

// ResolveSDKDestination applies the D18 default: an explicit setting wins,
// else both when signedIn and this machine receives app data (localOn),
// online when signedIn and it does not (E-32), else local. An invalid
// explicit value (one that Validate would refuse) resolves as unset.
func ResolveSDKDestination(c ObservabilitySDKConfig, signedIn, localOn bool) SDKDestinationResolution {
	configured := strings.TrimSpace(c.Destination)
	if validateObservabilitySDK(ObservabilitySDKConfig{Destination: configured}) != nil {
		configured = ""
	}
	for _, r := range sdkDestinationRules {
		if r.match(configured, signedIn, localOn) {
			return SDKDestinationResolution{Destination: r.destination(configured), Source: r.source, Configured: configured}
		}
	}
	return SDKDestinationResolution{Destination: SDKDestinationLocal, Source: "default_not_signed_in"}
}

// SDKDestinationSendsOnline reports whether an explicit destination value
// sends data off this machine (online or both). It judges the value as
// written: an unset destination resolves to both on a signed-in machine (the
// D18 default), so an agent's write is gated on SDKDestinationKeepsLocal, not
// on this (review finding R-B02).
func SDKDestinationSendsOnline(d string) bool {
	d = strings.TrimSpace(d)
	return d == SDKDestinationOnline || d == SDKDestinationBoth
}

// SDKDestinationKeepsLocal reports whether a destination value keeps an app's
// data on this machine whatever the sign-in state: only the literal local. An
// unset value ("", the default) is not one, because a signed-in machine
// resolves it to both (ResolveSDKDestination). D19 lets an agent apply only
// such a value directly (review finding R-B02).
func SDKDestinationKeepsLocal(d string) bool {
	return strings.TrimSpace(d) == SDKDestinationLocal
}
