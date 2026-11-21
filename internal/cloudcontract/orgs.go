package cloudcontract

import (
	"fmt"
	"strings"
)

// orgs.go is the wire contract of the node's organization discovery (managed
// SaaS plan 06 section 19.3 rows 7-9; plan 07 M8.4 and M8.7): the two
// device-authenticated calls `observer connect` makes when it is given no
// server address.
//
//	GET  /v1/orgs                   DeviceOrgList: the orgs the signed-in
//	                                account belongs to, personal first.
//	POST /v1/orgs/personal:ensure   EnsurePersonalOrgResponse: the account's
//	                                personal org, created lazily.
//
// The server (internal/cloudserver/api) builds these values; the node
// (internal/cloudclient, through the consent gateway's Bootstrap family)
// decodes and validates them. Every host and URL is built by the server from
// the org's slug and its configured tenant domain; the node never composes a
// tenant host, it only checks that what it was given is an https URL whose
// host is the org's own slug label.

// DeviceOrgKind is the kind of an org as the discovery wire carries it.
type DeviceOrgKind string

// The two org kinds (the cloud registry's orgs.kind vocabulary).
const (
	DeviceOrgPersonal DeviceOrgKind = "personal"
	DeviceOrgTeam     DeviceOrgKind = "team"
)

// DeviceOrgStatus is an org's lifecycle state on the discovery wire (the
// platform contract's tenant states).
type DeviceOrgStatus string

// The org lifecycle states a node may see.
const (
	DeviceOrgProvisioning    DeviceOrgStatus = "provisioning"
	DeviceOrgActive          DeviceOrgStatus = "active"
	DeviceOrgSuspended       DeviceOrgStatus = "suspended"
	DeviceOrgPendingDeletion DeviceOrgStatus = "pending_deletion"
	DeviceOrgPurging         DeviceOrgStatus = "purging"
	DeviceOrgPurged          DeviceOrgStatus = "purged"
)

// knownDeviceOrgStatus is the closed status vocabulary.
var knownDeviceOrgStatus = map[DeviceOrgStatus]bool{
	DeviceOrgProvisioning: true, DeviceOrgActive: true, DeviceOrgSuspended: true,
	DeviceOrgPendingDeletion: true, DeviceOrgPurging: true, DeviceOrgPurged: true,
}

// Attachable reports whether a machine may attach to an org in this state:
// only an active org has a tenant that answers enrolment.
func (s DeviceOrgStatus) Attachable() bool { return s == DeviceOrgActive }

// DeviceOrg is one org on the discovery wire.
type DeviceOrg struct {
	OrgID       string          `json:"org_id"`
	Slug        string          `json:"slug"`
	DisplayName string          `json:"display_name"`
	Kind        DeviceOrgKind   `json:"kind"`
	Status      DeviceOrgStatus `json:"status"`
	// Tenancy is the org's enrolment tenancy: "individual" for a personal
	// org (always), "managed" for a team org created from the console.
	Tenancy string `json:"tenancy"`
	// ServerURL is the tenant's base URL (https://<slug>.<tenant domain>),
	// the address `observer enroll` attaches to. Empty when the deployment
	// has no tenant domain configured, or while the org is not active.
	ServerURL string `json:"server_url,omitempty"`
	// Stage is the create's progress word while the org is provisioning
	// (the console's vocabulary: queued, creating, waitlisted, retrying,
	// finishing, failed, unknown); empty otherwise.
	Stage string `json:"stage,omitempty"`
}

// DeviceOrgList is GET /v1/orgs.
type DeviceOrgList struct {
	Orgs []DeviceOrg `json:"orgs"`
}

// EnsurePersonalOrgResponse is POST /v1/orgs/personal:ensure.
type EnsurePersonalOrgResponse struct {
	Org DeviceOrg `json:"org"`
	// Created is true when this call created the org (false: it already
	// existed).
	Created bool `json:"created"`
}

// MaxDeviceOrgs bounds the list a node accepts.
const MaxDeviceOrgs = 200

// Validate checks one org's shape: the closed vocabularies, the personal
// org's individual tenancy, and a server URL that is https and names the
// org's own slug as its first host label.
func (o DeviceOrg) Validate() error {
	if strings.TrimSpace(o.OrgID) == "" || strings.TrimSpace(o.Slug) == "" {
		return fmt.Errorf("cloudcontract.DeviceOrg: org_id and slug are required")
	}
	switch o.Kind {
	case DeviceOrgPersonal:
		if o.Tenancy != "individual" {
			return fmt.Errorf("cloudcontract.DeviceOrg: a personal org must be individual, got %q", o.Tenancy)
		}
	case DeviceOrgTeam:
		if o.Tenancy != "individual" && o.Tenancy != "managed" {
			return fmt.Errorf("cloudcontract.DeviceOrg: unknown tenancy %q", o.Tenancy)
		}
	default:
		return fmt.Errorf("cloudcontract.DeviceOrg: unknown kind %q", o.Kind)
	}
	if !knownDeviceOrgStatus[o.Status] {
		return fmt.Errorf("cloudcontract.DeviceOrg: unknown status %q", o.Status)
	}
	if o.ServerURL != "" {
		rest, ok := strings.CutPrefix(o.ServerURL, "https://")
		if !ok {
			return fmt.Errorf("cloudcontract.DeviceOrg: server_url must be https")
		}
		host, _, _ := strings.Cut(rest, "/")
		label, _, _ := strings.Cut(host, ".")
		if label != o.Slug || !strings.Contains(host, ".") {
			return fmt.Errorf("cloudcontract.DeviceOrg: server_url host must be <slug>.<domain>")
		}
	}
	return nil
}

// Validate checks every org and the list bound.
func (l DeviceOrgList) Validate() error {
	if len(l.Orgs) > MaxDeviceOrgs {
		return fmt.Errorf("cloudcontract.DeviceOrgList: %d orgs exceeds %d", len(l.Orgs), MaxDeviceOrgs)
	}
	for i, o := range l.Orgs {
		if err := o.Validate(); err != nil {
			return fmt.Errorf("orgs[%d]: %w", i, err)
		}
	}
	return nil
}

// Validate checks the ensured org is a personal one.
func (r EnsurePersonalOrgResponse) Validate() error {
	if err := r.Org.Validate(); err != nil {
		return err
	}
	if r.Org.Kind != DeviceOrgPersonal {
		return fmt.Errorf("cloudcontract.EnsurePersonalOrgResponse: kind %q is not personal", r.Org.Kind)
	}
	return nil
}
