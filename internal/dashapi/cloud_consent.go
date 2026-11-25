package dashapi

import (
	"bytes"
	"context"
	"strings"
	"time"
)

// cloudStartupNoticePrefix marks the process-startup lines internal/config
// prints to stderr (emitDeprecationOnce) when ~/.observer/config.toml still
// uses deprecated key aliases. They precede the child's real output because
// the runner captures stdout and stderr combined.
const cloudStartupNoticePrefix = "config: deprecation: "

// CloudStripStartupNotices drops the config-deprecation startup lines from a
// child's combined output so the preview panel shows ONLY what `observer cloud
// preview` printed about the session (the bytes, digests and summary) - the
// notices are about this machine's config file, not about what would upload,
// and the dashboard's Settings page already surfaces config migration. Every
// other line, including a real error, is kept verbatim.
func CloudStripStartupNotices(output string) string {
	if !strings.Contains(output, cloudStartupNoticePrefix) {
		return output
	}
	lines := strings.Split(output, "\n")
	kept := lines[:0]
	for _, l := range lines {
		if strings.HasPrefix(l, cloudStartupNoticePrefix) {
			continue
		}
		kept = append(kept, l)
	}
	return strings.Join(kept, "\n")
}

// RunOnce runs one `observer cloud <verb> <args...>` synchronously, bounded by
// timeout, and returns its combined output plus ok/exit_error - the shape
// every synchronous action route in this file shares (preview, consent,
// grant, revoke, delete-account).
func (c *CloudAccountSeams) RunOnce(ctx context.Context, verb string, args []string, timeout time.Duration) (output string, ok bool, exitError string) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var buf bytes.Buffer
	err := c.Run(ctx, verb, args, &buf)
	output = CloudStripStartupNotices(buf.String())
	return output, err == nil, CloudChildError(output, err)
}

// CloudChildError renders a failed child's error for the JSON exit_error
// field the way a person would read it: cobra prints the RunE error as an
// "Error: <message>" line on stderr, and THAT message is the reason (e.g.
// "bounded_context_enrichment" cannot be granted standing consent: …), while
// exec's err is only "exit status 1". The last "Error: " line wins when one
// exists; otherwise the exec error is returned verbatim; nil err ⇒ "".
func CloudChildError(output string, err error) string {
	if err == nil {
		return ""
	}
	msg := ""
	for _, l := range strings.Split(output, "\n") {
		if strings.HasPrefix(l, cloudChildErrorPrefix) {
			msg = strings.TrimSpace(strings.TrimPrefix(l, cloudChildErrorPrefix))
		}
	}
	if msg != "" {
		return msg
	}
	return err.Error()
}

// cloudChildErrorPrefix is cobra's error-line prefix on stderr.
const cloudChildErrorPrefix = "Error: "
