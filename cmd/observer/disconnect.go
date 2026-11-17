package main

import "github.com/spf13/cobra"

// disconnect.go is `observer disconnect` (Getting started v2): the undo of
// `observer connect`, under the word the rest of the product uses. It is the
// existing leave command (`observer unenroll`, performUnenrol in org.go), so
// the two can never drift apart; only the name and the opening help differ.
// The SuperBased sign-in is kept (`observer cloud logout` signs out).

func newDisconnectCmd() *cobra.Command { return asDisconnectCmd(newUnenrollCmd()) }

// asDisconnectCmd renames a built leave command to `disconnect`.
func asDisconnectCmd(c *cobra.Command) *cobra.Command {
	c.Use = "disconnect"
	c.Short = "Disconnect this machine from its personal dashboard or team"
	c.Long = `Stops sending from this machine and removes its connection. Your sign-in,
config.toml and everything on this machine stay; nothing already sent is
deleted online. Connect again any time with ` + "`observer connect`" + `.

` + c.Long
	return c
}
