package cloudclient

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

// A proof-of-possession carries its signing time, and the server accepts it
// only within its clock window (60 s by default). A machine whose clock is a
// few minutes off (a fresh VM, a laptop back from sleep without NTP) had every
// signed request refused: `observer connect` failed with a bare 401 (L-142).
// The client therefore signs on the SERVER's clock: every response's Date
// header tells it how far this machine's clock is off, and later proofs are
// signed with that difference applied.
const (
	// skewAdopt is the smallest difference the client corrects for. Below
	// it the local clock is trusted: a Date header has one-second resolution
	// and the server's window is far wider.
	skewAdopt = 5 * time.Second
	// skewMax bounds a believable difference; a Date header further off is
	// ignored rather than trusted.
	skewMax = 7 * 24 * time.Hour
)

// proofRejectedBody is the server's refusal of a proof-of-possession
// (internal/cloudserver/api: "proof-of-possession failed").
const proofRejectedBody = "proof-of-possession failed"

// learnSkew records how far the server's clock, read from a response's Date
// header, is from this machine's clock at local. A missing or unparseable
// header, or one further off than skewMax, changes nothing; a difference
// under skewAdopt resets the correction to zero.
func (c *Client) learnSkew(dateHeader string, local time.Time) {
	if dateHeader == "" {
		return
	}
	server, err := http.ParseTime(dateHeader)
	if err != nil {
		return
	}
	d := server.Sub(local)
	if d > skewMax || d < -skewMax {
		return
	}
	if d < skewAdopt && d > -skewAdopt {
		d = 0
	}
	c.skew.Store(int64(d))
}

// proofTime is the time a proof is signed with: this machine's clock moved by
// the learned difference.
func (c *Client) proofTime() time.Time {
	return c.clock().Add(time.Duration(c.skew.Load()))
}

// ClockSkew reports how far the server's clock was ahead of this machine's
// (negative when behind) at the last response, or zero when the two agree
// within skewAdopt or no response has been read yet.
func (c *Client) ClockSkew() time.Duration {
	return time.Duration(c.skew.Load())
}

// IsProofRejected reports whether err is the server refusing a request's
// proof-of-possession (a 401 whose body says so).
func IsProofRejected(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized &&
		strings.Contains(apiErr.Body, proofRejectedBody)
}
