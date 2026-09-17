package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgclient"
)

// ACP-P6c IdP-driven managed enrolment, CLI half (plan
// docs/plans/acp-p6c-idp-managed-enrolment-plan-2026-08-20.md §5).
//
// `observer enroll --idp <org-url>` prints a short code and a URL, the
// developer signs in with their enterprise IdP on ANY device and approves, and
// this loop polls until the organisation hands over an ordinary one-time
// enrolment code. That code then goes through the UNCHANGED enrol path, so
// everything downstream — the managed-tenancy response, the signed grant, the
// P6a machine bind — behaves exactly as it does on the code rail.
//
// Nothing here needs a TTY. That is the point: org-provisioned fleets enrol
// over SSH, and the device-code shape is what makes the browser step possible
// on a machine that has no browser.

const (
	// idpDefaultInterval / idpDefaultDeadline apply when a server answers
	// without a cadence or a lifetime. They mirror the server's own values.
	idpDefaultInterval = 5 * time.Second
	idpDefaultDeadline = 10 * time.Minute
	// idpSlowDownStep is added to the wait each time the server says
	// slow_down. Backing off ADDITIVELY (rather than doubling) keeps a
	// briefly-busy server from pushing an otherwise healthy pairing past its
	// own expiry.
	idpSlowDownStep = 5 * time.Second
	// idpMaxInterval bounds that backoff for the same reason.
	idpMaxInterval = 30 * time.Second
)

// idpEnrolFlow runs one device-code pairing to completion. The clock and the
// browser opener are injected so the loop is testable without real sleeping
// and without launching anything on the machine running the tests.
type idpEnrolFlow struct {
	client *orgclient.Client
	out    io.Writer
	// sleep defaults to time.Sleep, now to time.Now, open to openBrowser.
	sleep func(time.Duration)
	now   func() time.Time
	open  func(string)
}

func (f *idpEnrolFlow) sleepFor(d time.Duration) {
	if f.sleep != nil {
		f.sleep(d)
		return
	}
	time.Sleep(d)
}

func (f *idpEnrolFlow) timeNow() time.Time {
	if f.now != nil {
		return f.now()
	}
	return time.Now()
}

// Run returns the one-time enrolment code an approval produced. Every failure
// is ONE plain sentence a developer can act on: this is the first thing a new
// machine does, and a stack of jargon here is a support ticket.
func (f *idpEnrolFlow) Run(ctx context.Context, orgURL string) (string, error) {
	start, err := f.client.StartIdPEnrol(ctx, orgURL)
	if err != nil {
		if errors.Is(err, orgclient.ErrIdPEnrolUnavailable) {
			return "", errors.New("this organisation does not offer sign-in enrolment (it may be switched off, or the server may be older than the feature).\n" +
				"  Ask an administrator for an enrolment code and run `observer enroll <org-url> <code>` instead")
		}
		return "", err
	}
	f.announce(start)

	interval := durationOrDefault(start.Interval, idpDefaultInterval)
	deadline := f.timeNow().Add(durationOrDefault(start.ExpiresIn, idpDefaultDeadline))

	for {
		// Wait FIRST: the human has to reach a browser, and the server
		// answers slow_down to a poll that arrives inside the interval.
		f.sleepFor(interval)
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if f.timeNow().After(deadline) {
			return "", fmt.Errorf("nobody approved code %s in time. Run `observer enroll --idp %s` again to get a fresh code", start.UserCode, orgURL)
		}

		res, err := f.client.PollIdPEnrol(ctx, orgURL, start.DeviceCode)
		if err != nil {
			if errors.Is(err, orgclient.ErrIdPEnrolUnavailable) {
				// Mid-flow this is the pairing being gone rather than the
				// feature being absent — the server deliberately answers the
				// same way to both so a poll cannot enumerate live pairings.
				return "", fmt.Errorf("the organisation no longer recognises code %s. Run `observer enroll --idp %s` again to get a fresh code", start.UserCode, orgURL)
			}
			return "", err
		}

		switch res.Status {
		case orgclient.IdPStatusApproved:
			fmt.Fprintln(f.out, "Approved. Completing enrolment.")
			return res.OneTimeToken, nil
		case orgclient.IdPStatusPending:
			// Keep waiting, quietly. A line per poll would bury the code the
			// developer still has to read off the screen.
		case orgclient.IdPStatusSlowDown:
			interval = backoff(interval, res.Interval)
		case orgclient.IdPStatusDenied:
			return "", errors.New("the enrolment was refused in the browser. Nothing was granted and this machine is not enrolled")
		case orgclient.IdPStatusExpired:
			return "", fmt.Errorf("code %s expired before it was approved. Run `observer enroll --idp %s` again to get a fresh code", start.UserCode, orgURL)
		default:
			return "", fmt.Errorf("the organisation answered with an enrolment state this version of Observer does not understand (%q); upgrade Observer, or ask an administrator for an enrolment code", res.Status)
		}
	}
}

// announce prints what the developer has to act on, and opens a local browser
// if this machine happens to have one. The print is the contract; the browser
// is a convenience that must never be required, because the machine being
// enrolled is frequently headless and the whole design lets the human use a
// different device.
func (f *idpEnrolFlow) announce(start orgclient.IdPEnrolStart) {
	fmt.Fprintln(f.out)
	fmt.Fprintln(f.out, "Sign in with your organisation account to enrol this machine.")
	fmt.Fprintln(f.out, "You need an active dashboard account on that organisation first (redeem your")
	fmt.Fprintln(f.out, "sign-in invite and sign in once). Then open the URL below, sign in if asked,")
	fmt.Fprintln(f.out, "and enter the code.")
	fmt.Fprintln(f.out, "You can do this on any device - a phone or another computer is fine.")
	fmt.Fprintln(f.out)
	hintedURI := verificationURIWithCodeHint(start.VerificationURI, start.UserCode)
	fmt.Fprintf(f.out, "    Open:  %s\n", hintedURI)
	fmt.Fprintf(f.out, "    Enter: %s\n", start.UserCode)
	fmt.Fprintln(f.out)
	fmt.Fprintf(f.out, "Waiting for approval (the code is good for about %s). Press Ctrl-C to stop.\n",
		durationOrDefault(start.ExpiresIn, idpDefaultDeadline).Round(time.Minute))

	if start.VerificationURI == "" {
		return
	}
	// Open the SAME hinted URL that was just printed, so a browser that opens
	// automatically pre-fills the code exactly like a developer who copy-
	// pasted the "Open:" line above would get — instead of landing on a bare
	// sign-in page that silently drops the code hint.
	if f.open != nil {
		f.open(hintedURI)
		return
	}
	openBrowser(hintedURI)
}

// verificationURIWithCodeHint appends ?user_code=<code> to the verification
// URL as a convenience hint some servers can use to pre-fill the sign-in
// page's code field (added once the server bundle lands: `/enrol/idp?user_code=<CODE>`).
// A server that ignores the query parameter just shows its ordinary sign-in
// page, and the plain "Enter:" line printed alongside this URL still carries
// the code for the developer to type by hand — this is a hint, never the
// only way to supply the code. Malformed input degrades to the original URI
// rather than failing the whole announcement.
func verificationURIWithCodeHint(verificationURI, userCode string) string {
	if verificationURI == "" || userCode == "" {
		return verificationURI
	}
	u, err := url.Parse(verificationURI)
	if err != nil {
		return verificationURI
	}
	q := u.Query()
	q.Set("user_code", userCode)
	u.RawQuery = q.Encode()
	return u.String()
}

// durationOrDefault converts a server-supplied second count, falling back when
// it is absent or nonsensical. A zero interval would busy-poll a server that
// asked for a cadence it forgot to state.
func durationOrDefault(seconds int, fallback time.Duration) time.Duration {
	if seconds <= 0 {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}

// backoff widens the poll interval after a slow_down, honouring a larger
// cadence the server states and bounded by idpMaxInterval.
func backoff(current time.Duration, serverSeconds int) time.Duration {
	next := current + idpSlowDownStep
	if asked := durationOrDefault(serverSeconds, 0); asked > next {
		next = asked
	}
	if next > idpMaxInterval {
		next = idpMaxInterval
	}
	return next
}
