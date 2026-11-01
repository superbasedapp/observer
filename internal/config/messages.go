package config

// MessagesConfig is the developer's [messages] section: where messages from
// the org's admins surface on this machine
// (docs/plans/admin-developer-messaging-plan-2026-10-15.md sections 8 and 9,
// operator ruling D-688 1).
//
// It is LOCAL-ONLY and the developer owns it: the org has no remote toggle
// for any of these keys (the full_content precedent). Muting a surface never
// hides a message from the Messages page, which is the source of truth; a
// developer can mute every push surface but cannot block an admin message
// from the inbox. Every key is read when it is used, so a change applies
// without a restart.
type MessagesConfig struct {
	// Toast shows an in-dashboard toast when a new message arrives while the
	// dashboard is open. Default true.
	Toast bool `toml:"toast"`
	// VSCode shows the VS Code notification and the status bar badge for new
	// messages. Default true.
	VSCode bool `toml:"vscode"`
	// Statusline adds the "messages" segment to `observer statusline` while
	// something is unread ("1 message from your admin"); it never shows
	// message text. Default true.
	Statusline bool `toml:"statusline"`
	// Desktop sends an operating-system notification (sender and subject
	// only) once per new admin message. Default false: the developer turns
	// it on.
	Desktop bool `toml:"desktop"`
	// AlertsOnly limits every push surface (bell, toast, VS Code, status
	// line, desktop) to messages the admin marked as an alert. The Messages
	// page still lists everything. Default false.
	AlertsOnly bool `toml:"alerts_only"`
	// ReadReceipts lets your admins see when you have read a message. It is
	// honoured on an INDIVIDUAL enrolment only: a managed (org-provisioned)
	// node always sends read receipts (the enterprise full-capture ruling).
	// Acknowledging a message is an explicit act and is always reported.
	// Default true.
	ReadReceipts bool `toml:"read_receipts"`
}

// DefaultMessagesConfig is the [messages] default: every in-editor surface
// on, the desktop notification off, all messages on every surface, read
// receipts on.
func DefaultMessagesConfig() MessagesConfig {
	return MessagesConfig{
		Toast:        true,
		VSCode:       true,
		Statusline:   true,
		Desktop:      false,
		AlertsOnly:   false,
		ReadReceipts: true,
	}
}
