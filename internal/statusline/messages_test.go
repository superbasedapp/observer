package statusline

import (
	"strings"
	"testing"
)

// TestMessagesSegment: the messages segment renders a count only while a
// message from the org's admins is unread, so every other node's line is
// unchanged (T-854).
func TestMessagesSegment(t *testing.T) {
	base := Render(Input{}, DaemonTile{}, RenderOptions{})
	cases := []struct {
		unread int
		want   string
	}{
		{0, ""},
		{-1, ""},
		{1, "1 message from your admin"},
		{3, "3 messages from your admins"},
	}
	for _, tc := range cases {
		got := Render(Input{}, DaemonTile{MessagesUnread: tc.unread}, RenderOptions{})
		if tc.want == "" {
			if got != base {
				t.Fatalf("unread=%d changed the line: %q, want %q", tc.unread, got, base)
			}
			continue
		}
		if !strings.Contains(got, tc.want) {
			t.Fatalf("unread=%d: %q missing %q", tc.unread, got, tc.want)
		}
	}
}
