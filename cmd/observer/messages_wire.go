package main

import (
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard/notify"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
)

// Admin and developer messaging, daemon wiring (T-854,
// docs/plans/admin-developer-messaging-plan-2026-10-15.md section 8).
//
// The org client owns the rail; this file only hands it the developer's
// [messages] section (read at use time, so a change applies without a
// restart) and the one side effect the daemon owns: an OS desktop
// notification for a new admin message, OFF unless the developer turned on
// [messages].desktop (D-688 ruling 1). Sender and subject only, never the
// body, at most once per message (the org client hands each newly stored
// message to the sink exactly once).

// maxDesktopMessageNotices bounds the toasts one pull may raise; anything
// beyond is folded into one "N more" notice, so a burst never floods the
// desktop.
const maxDesktopMessageNotices = 3

// wireOrgMessages installs the [messages] reader and the desktop sink.
func wireOrgMessages(c *orgclient.Client, configPath string) {
	if c == nil {
		return
	}
	settings := messagesSettingsReader(configPath)
	c.SetMessagesSettings(settings)
	desktop := notify.NewDesktop()
	c.SetOrgMessageSink(func(notices []orgclient.OrgMessageNotice) {
		for _, n := range desktopMessageNotices(notices, settings()) {
			desktop.Notify(n.title, n.body)
		}
	})
}

// messagesSettingsReader reads [messages] from the config file each call,
// falling back to the defaults when the file cannot be read.
func messagesSettingsReader(configPath string) func() config.MessagesConfig {
	return func() config.MessagesConfig {
		cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
		if err != nil {
			return config.DefaultMessagesConfig()
		}
		return cfg.Messages
	}
}

// desktopNotice is one OS notification.
type desktopNotice struct{ title, body string }

// desktopMessageNotices decides which new admin messages raise a desktop
// notification under the developer's choices. Pure: table-tested.
func desktopMessageNotices(notices []orgclient.OrgMessageNotice, m config.MessagesConfig) []desktopNotice {
	if !m.Desktop {
		return nil
	}
	var keep []orgclient.OrgMessageNotice
	for _, n := range notices {
		if m.AlertsOnly && n.Kind != "alert" {
			continue
		}
		keep = append(keep, n)
	}
	out := make([]desktopNotice, 0, maxDesktopMessageNotices)
	for i, n := range keep {
		if i == maxDesktopMessageNotices-1 && len(keep) > maxDesktopMessageNotices {
			out = append(out, desktopNotice{
				title: "Messages from your admins",
				body:  fmt.Sprintf("%d more messages are waiting in Observer.", len(keep)-i),
			})
			break
		}
		subject := strings.TrimSpace(n.Subject)
		if subject == "" {
			subject = "New message"
		}
		title := "your admin"
		if author := strings.TrimSpace(n.AuthorName); author != "" {
			title = author + " (admin)"
		}
		if n.Kind == "alert" {
			title = "Alert from " + title
		} else {
			title = "Message from " + title
		}
		out = append(out, desktopNotice{title: title, body: subject})
	}
	return out
}
