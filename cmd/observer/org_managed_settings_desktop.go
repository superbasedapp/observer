package main

import (
	"path"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/managedsettings"
)

// The claude-desktop Rail B provider of `observer org emit-managed-settings`
// (surface-gap CC-1b / OBS-8c, decision D1): Claude Desktop's gateway route
// in the Desktop's own managed policy layer. It is an explicit admin option
// (--desktop-gateway-route) because live check LC2 has not run.

// emitDesktopFlags are the claude-desktop-only switches.
type emitDesktopFlags struct {
	gatewayRoute           bool
	helper, helperWin      string
	helperArgs             []string
	authScheme, identifier string
}

func addEmitDesktopFlags(cmd *cobra.Command, f *emitDesktopFlags) {
	cmd.Flags().BoolVar(&f.gatewayRoute, "desktop-gateway-route", false,
		"[claude-desktop] route Claude Desktop through the proxy in gateway mode (needs a gateway credential, drops\n"+
			"Anthropic cloud environments and Remote Control; not live-verified, "+managedsettings.ClaudeDesktopLiveCheck+")")
	cmd.Flags().StringVar(&f.helper, "credential-helper", "", "[claude-desktop] absolute path of the executable that prints the gateway credential (Linux / macOS)")
	cmd.Flags().StringVar(&f.helperWin, "credential-helper-windows", "", "[claude-desktop] absolute path of the Windows credential helper")
	cmd.Flags().StringArrayVar(&f.helperArgs, "credential-helper-arg", nil, "[claude-desktop] argument for the credential helper (repeatable)")
	cmd.Flags().StringVar(&f.authScheme, "gateway-auth-scheme", managedsettings.DefaultClaudeDesktopAuthScheme, "[claude-desktop] how the credential is sent: x-api-key or bearer")
	cmd.Flags().StringVar(&f.identifier, "profile-identifier", "", "[claude-desktop] reverse-DNS stem of the generated profile id (default "+managedsettings.DefaultIdentifier+")")
}

type emitDesktopArgs struct {
	scope, outDir, gatewayBaseURL string
	flags                         emitDesktopFlags
}

func runEmitClaudeDesktop(cmd *cobra.Command, a emitDesktopArgs) error {
	arts, err := managedsettings.GenerateClaudeDesktop(managedsettings.ClaudeDesktopOptions{
		GatewayRoute:            a.flags.gatewayRoute,
		GatewayBaseURL:          a.gatewayBaseURL,
		CredentialHelper:        a.flags.helper,
		CredentialHelperWindows: a.flags.helperWin,
		CredentialHelperArgs:    a.flags.helperArgs,
		AuthScheme:              a.flags.authScheme,
		Identifier:              a.flags.identifier,
	})
	if err != nil {
		return err
	}
	var files []emittedFile
	for _, art := range arts.Artifacts {
		data := art.Bytes()
		if a.outDir == "" {
			// Print the registry text, not its UTF-16 bytes.
			data = []byte(art.Content)
		}
		deploy := string(art.Channel)
		if len(art.Install) > 0 && art.Install[0].Path != "" {
			deploy = art.Install[0].Path
		}
		files = append(files, emittedFile{path.Base(art.Name), data, deploy})
	}
	files = append(files, emittedFile{"README.md", []byte(arts.Readme), ""})
	return emitFiles(cmd, a.scope, a.outDir, files)
}
