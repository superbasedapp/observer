package main

import (
	"errors"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgenrol"
)

// orgenrol_drain.go renders the switch / leave drain (R3-78, operator ruling
// D-22) for both surfaces. The rule itself lives in internal/orgclient
// (drain.go): before this machine leaves an organization or enrols with a
// different one, the rows still waiting for the current organization are sent
// to it; when that fails, nothing changes unless the person chose to drop
// them (`--drop-unsent` on the CLI, "Switch anyway" / "Leave anyway" on the
// dashboard). This file only words it, once, so the CLI and the dashboard say
// the same thing.

// switchDrainOptions builds the drain options from the node's config: org
// push switched off ([org_client] enabled = false) is the person's own choice
// not to send anything, so the drain sends nothing and says why.
func switchDrainOptions(cfg *config.Config, dropUnsent bool) orgclient.DrainOptions {
	opts := orgclient.DrainOptions{DropUnsent: dropUnsent}
	if cfg != nil && !cfg.OrgClient.Enabled {
		opts.PushOffReason = "org push is turned off in config.toml ([org_client] enabled = false), so they were not sent"
	}
	return opts
}

// drainOrg names the drained organization.
func drainOrg(rep orgclient.DrainReport) string {
	if n := orgenrol.DisplayName(rep.OrgID, rep.OrgServerURL, rep.OrgName); n != "" {
		return n
	}
	if rep.OrgID != "" {
		return rep.OrgID
	}
	return "the current organization"
}

// unsentTail is what happens to rows the person chose to drop, in one
// sentence both refusals and the dropped note end with.
const unsentTail = "they stay on this machine, unsent; only `observer org backfill --all --confirm` would ever send them, " +
	"and it sends this machine's whole history to the organization it is enrolled in at that time."

// drainSurface is how one surface names the explicit choice.
type drainSurface struct {
	switchAnyway string
	leaveAnyway  string
}

var (
	cliDrainSurface  = drainSurface{switchAnyway: "add --drop-unsent to switch anyway", leaveAnyway: "add --drop-unsent to leave anyway"}
	dashDrainSurface = drainSurface{switchAnyway: "choose Switch anyway", leaveAnyway: "choose Leave anyway"}
)

// unsentRefusalText is the refusal sentence for a switch (leave=false) or a
// leave (leave=true).
func unsentRefusalText(rep orgclient.DrainReport, leave bool, s drainSurface) string {
	org := drainOrg(rep)
	verb, choice := "Not switched", s.switchAnyway
	if leave {
		verb, choice = "Did not leave", s.leaveAnyway
	}
	return fmt.Sprintf("%s: %d rows captured for %s have not been sent to it yet, and sending them failed: %s. "+
		"This machine is still enrolled in %s and nothing was changed. Try again once %s accepts them, or %s: %s",
		verb, rep.Remaining, org, rep.Reason, org, org, choice, unsentTail)
}

// unsentRefusal reports whether err is the drain refusal and, if so, its text.
func unsentRefusal(err error, leave bool, s drainSurface) (string, bool) {
	var ue *orgclient.UnsentRowsError
	if !errors.As(err, &ue) {
		return "", false
	}
	return unsentRefusalText(ue.Report, leave, s), true
}

// drainNote is the line a finished switch or leave prints about the drain:
// how many rows were sent first, or which rows were left and why. Empty when
// there was nothing to say (no previous enrolment, nothing waiting).
// dropRequested tells a person-chosen drop from the same-server case, where
// the other organization is only known once the code is spent.
func drainNote(rep orgclient.DrainReport, leave, dropRequested bool) (text string, warn bool) {
	if !rep.Attempted {
		return "", false
	}
	org := drainOrg(rep)
	before := "before switching"
	if leave {
		before = "before leaving"
	}
	switch {
	case rep.Dropped && dropRequested:
		verb := "Switched anyway"
		if leave {
			verb = "Left anyway"
		}
		return fmt.Sprintf("%s: %d rows captured for %s were not sent (%s); %s", verb, rep.Remaining, org, rep.Reason, unsentTail), true
	case rep.Dropped:
		return fmt.Sprintf("%d rows captured for %s were not sent (%s). The server now answers for a different organization, "+
			"which is known only once the enrolment code is used, so the switch went ahead; %s", rep.Remaining, org, rep.Reason, unsentTail), true
	case rep.Sent > 0:
		return fmt.Sprintf("Sent %d pending rows to %s %s.", rep.Sent, org, before), false
	}
	return "", false
}
