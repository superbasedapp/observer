package keystore

import "errors"

// ServiceInfo describes one OS keychain service Observer writes: the service
// name, what it holds in plain words, the dashboard page that owns it, and
// the fixed record names a presence check may look for.
type ServiceInfo struct {
	// Service is the keychain service name (before Namespace is applied).
	Service string
	// Purpose says in plain words what is stored under the service.
	Purpose string
	// Owner is the dashboard path that manages the credential.
	Owner string
	// Records are the fixed record names stored under the service. Empty means
	// the record names depend on what the user added (a provider, a link, a
	// signing key id), so presence cannot be told from the service alone.
	Records []string
}

// services is the ONE table of keychain services Observer writes (the list
// `observer uninstall --all` clears and the You page shows). Literals, so it
// compiles in every omit-tag edition. cmd/observer's
// TestObserverKeystoreServicesAreListed keeps it whole.
var services = []ServiceInfo{
	{
		Service: "sbo-org-bearer-v1", Purpose: "Your organization sign-in and this machine's signing key", Owner: "/settings?section=enrolment",
		Records: []string{"bearer", "agent-signing-key"},
	},
	{
		Service: "sbo-cloud-credential-v1", Purpose: "Cloud Intelligence sign-in and this device's key", Owner: "/settings?section=cloud",
		Records: []string{"device-signing-key", "workos-refresh", "sbo-api-token"},
	},
	{Service: "sbo-plans-v1", Purpose: "Keys for the plan and balance accounts you added", Owner: "/plans"},
	{Service: "sbo-delivery-v1", Purpose: "Tokens for the report delivery links you added", Owner: "/settings?section=dashboard"},
	{Service: "sbo-cloudagents-v1", Purpose: "Keys for the cloud agent connectors you added", Owner: "/settings?section=cloud"},
	{Service: "sbo-sandbox-cred-v1", Purpose: "Provider keys handed to sandboxed runs", Owner: "/terminals"},
	{Service: "sbo-sandbox-e2b-v1", Purpose: "Hosted sandbox sign-in (E2B)", Owner: "/terminals"},
	{Service: "sbo-sandbox-modal-v1", Purpose: "Hosted sandbox sign-in (Modal)", Owner: "/terminals"},
	{Service: "sbo-sandbox-vercel-v1", Purpose: "Hosted sandbox sign-in (Vercel)", Owner: "/terminals"},
	{Service: "sbo-sandbox-docker-v1", Purpose: "Hosted sandbox sign-in (Docker Sandboxes)", Owner: "/terminals"},
	{Service: "sbo-sandbox-daytona-v1", Purpose: "Hosted sandbox sign-in (Daytona)", Owner: "/terminals"},
	{Service: "sbo-change-record-v1", Purpose: "Keys that sign your security change records", Owner: "/code-security?tab=baselines"},
	{
		Service: "sbo-exec-evidence-v1", Purpose: "Key that seals run evidence", Owner: "/terminals",
		Records: []string{"exec-evidence-seal-key"},
	},
	{Service: "sbo-sandbox-instabox-v1", Purpose: "Hosted sandbox sign-in (InstaBox)", Owner: "/terminals"},
	{
		Service: "sbo-sdk-credential-v1", Purpose: "Your SDK key for sending your apps' data to your organization", Owner: "/settings?section=observability",
		Records: []string{"sdk-credential"},
	},
}

// Services returns a copy of the keychain service table, in display order.
func Services() []ServiceInfo {
	out := make([]ServiceInfo, len(services))
	for i, s := range services {
		s.Records = append([]string(nil), s.Records...)
		out[i] = s
	}
	return out
}

// ServiceNames returns just the service names, in table order.
func ServiceNames() []string {
	out := make([]string, len(services))
	for i, s := range services {
		out[i] = s.Service
	}
	return out
}

// Presence is the answer of one presence check.
type Presence string

// The three answers a presence check can give.
const (
	// PresencePresent: at least one fixed record exists.
	PresencePresent Presence = "present"
	// PresenceAbsent: every fixed record is absent.
	PresenceAbsent Presence = "absent"
	// PresenceUnknown: the service has no fixed record names, so presence
	// depends on what the user added. Never rendered as absent.
	PresenceUnknown Presence = "unknown"
	// PresenceUnavailable: the OS keychain itself could not be read (no
	// keychain service on this machine, or it is locked). Never rendered as
	// absent.
	PresenceUnavailable Presence = "unavailable"
)

// CheckPresence reports whether any of info's fixed records exists under the
// service in this Observer home. The secret read to learn that is dropped at
// once; no value leaves this function.
func CheckPresence(info ServiceInfo) Presence {
	if len(info.Records) == 0 {
		return PresenceUnknown
	}
	unreadable := false
	for _, rec := range info.Records {
		_, err := KeyringGet(info.Service, rec) // the value is discarded unread
		switch {
		case err == nil:
			return PresencePresent
		case errors.Is(err, ErrKeyringNotFound):
		default:
			unreadable = true
		}
	}
	if unreadable {
		return PresenceUnavailable
	}
	return PresenceAbsent
}

// CheckPresenceAll runs CheckPresence for each service, in order. When any
// read shows the keychain itself cannot be read, a service without fixed
// record names is reported unavailable too rather than unknown: the reason
// it cannot be told is the keychain, not what the user added.
func CheckPresenceAll(infos []ServiceInfo) []Presence {
	out := make([]Presence, len(infos))
	unavailable := false
	for i, in := range infos {
		out[i] = CheckPresence(in)
		if out[i] == PresenceUnavailable {
			unavailable = true
		}
	}
	if unavailable {
		for i, p := range out {
			if p == PresenceUnknown {
				out[i] = PresenceUnavailable
			}
		}
	}
	return out
}
