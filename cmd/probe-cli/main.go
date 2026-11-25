package main

import (
	"context"
	"fmt"
	"os"

	"github.com/marmutapp/superbased-observer/internal/adapter/antigravity"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: probe-cli <path-to-.pb>")
		os.Exit(2)
	}
	path := os.Args[1]
	a := antigravity.New().WithNetworkRecovery("local")
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ParseSessionFile error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("NewOffset=%d RetrySuggested=%v\n", res.NewOffset, res.RetrySuggested)
	fmt.Printf("ToolEvents=%d TokenEvents=%d Warnings=%d\n",
		len(res.ToolEvents), len(res.TokenEvents), len(res.Warnings))
	for i, w := range res.Warnings {
		fmt.Printf("  warn[%d]: %s\n", i, w)
	}
	for i, ev := range res.ToolEvents {
		if i >= 5 {
			fmt.Printf("  ... (+%d more events)\n", len(res.ToolEvents)-5)
			break
		}
		fmt.Printf("  tool[%d]: %s %s session=%s project=%q\n", i, ev.ActionType, ev.RawToolName, ev.SessionID, ev.ProjectRoot)
	}
}
