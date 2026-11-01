package hook

import (
	"fmt"
	"io"
	"strings"
)

// StderrBlockHeader opens every block reason a host shows through the hook's
// stderr (DEC-1, 2026-10-25). In a live check on the IBM Bob IDE the exit-2
// tool-gate block held, but the model read the bare stderr reason as the
// blocked tool's OUTPUT (the README it asked for). The header says, before
// the reason, that the text is Observer's block and not the tool's result.
const StderrBlockHeader = "Blocked by Observer guard:"

// StderrBlockReason returns reason as the text a host shows through stderr
// for a BLOCK: StderrBlockHeader, a space and the reason, on ONE first line
// (audit finding 5, operator ruling 2026-10-27), so a host that shows only
// the first stderr line still shows why; that one-line form is also the one
// the live checks (LC17b, batch 2) proved. An empty reason is the header
// alone. It is idempotent (a reason that already starts with the header, in
// this form or in the earlier header-on-its-own-line form an older Observer
// relays, is returned unchanged), so a relayed reason is never prefixed
// twice. It is the ONE place the header is added; it is for the stderr
// channel only, never for a JSON reply field, and never for a non-blocking
// warning.
func StderrBlockReason(reason string) string {
	if reason == "" {
		return StderrBlockHeader
	}
	if reason == StderrBlockHeader ||
		strings.HasPrefix(reason, StderrBlockHeader+" ") ||
		strings.HasPrefix(reason, StderrBlockHeader+"\n") ||
		strings.HasPrefix(reason, StderrBlockHeader+"\r\n") {
		return reason
	}
	return StderrBlockHeader + " " + reason
}

// WriteStderrBlockReason writes StderrBlockReason(reason) and a newline to w:
// the block reason of a host that shows the hook's stderr as that reason.
func WriteStderrBlockReason(w io.Writer, reason string) {
	fmt.Fprintln(w, StderrBlockReason(reason))
}
