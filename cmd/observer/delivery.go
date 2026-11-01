package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/delivery"
	"github.com/marmutapp/superbased-observer/internal/deliverynet"
	"github.com/marmutapp/superbased-observer/internal/deliverysvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// `observer delivery`: the CLI twin of the Projects "Delivery" tab and the
// Settings "Code hosts" card (D-689, docs/projects-page.md "Delivery").
// Every verb runs the same internal/deliverysvc calls the dashboard routes
// run, so the two never disagree. Nothing here reaches the network unless
// the verb's purpose is to (connect, test, check).

// deliveryTokenMaxBytes bounds what `connect --token-stdin` reads.
const deliveryTokenMaxBytes = 8 << 10

func newDeliveryCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "delivery",
		Short: "Commit to PR to merge tracking: code hosts, mirrors and per-project landing",
		Long: `Where AI-assisted commits went after you committed them: pushed, in a pull
request, merged, or landed on the default branch.

Local landing detection is on by default ([delivery].local) and reads only
your own git refs, as fresh as your last fetch. Nothing is sent anywhere until
you connect a code host (GitHub in this release) or opt a project into an
Observer-owned mirror. Observer never fetches in, or writes to, your
repository.`,
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.AddCommand(newDeliveryStatusCmd(), newDeliveryConnectCmd(), newDeliveryTestCmd(),
		newDeliveryDisconnectCmd(), newDeliveryCheckCmd(), newDeliveryMirrorsCmd(), newDeliveryProjectCmd())
	return cmd
}

// withDelivery opens config, database and a service for one CLI verb.
func withDelivery(cmd *cobra.Command, fn func(ctx context.Context, st *store.Store, svc *deliverysvc.Service) error) error {
	ctx := cmd.Context()
	configPath, _ := cmd.Flags().GetString("config")
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return err
	}
	defer cleanup()
	svc := newDeliveryService(cfg, database, newLogger(cfg.Observer.LogLevel))
	return fn(ctx, store.New(database), svc)
}

// deliveryCLIErr turns a service error into the plain sentence the
// dashboard shows for it.
func deliveryCLIErr(err error) error {
	var de *dashapi.DeliveryError
	if mapped := deliveryDashErr(err); errors.As(mapped, &de) {
		return errors.New(de.Message)
	}
	return err
}

// deliveryStatus is `observer delivery status --json`.
type deliveryStatus struct {
	Links     []dashapi.APIDeliveryLink   `json:"links"`
	Mirrors   []dashapi.APIDeliveryMirror `json:"mirrors"`
	UsedBytes int64                       `json:"mirror_used_bytes"`
	CapBytes  int64                       `json:"mirror_cap_bytes"`
	Projects  []deliveryProjectStatus     `json:"projects"`
}

// deliveryProjectStatus is one project's remotes, evidence source and
// freshness.
type deliveryProjectStatus struct {
	ProjectID int64                       `json:"project_id"`
	Root      string                      `json:"root"`
	Remotes   []dashapi.APIDeliveryRemote `json:"remotes"`
	Settings  dashapi.APIDeliverySettings `json:"settings"`
}

func newDeliveryStatusCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Code hosts, mirrors (size and cap) and each project's evidence source and freshness",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withDelivery(cmd, func(ctx context.Context, st *store.Store, svc *deliverysvc.Service) error {
				out, err := loadDeliveryStatus(ctx, st, svc)
				if err != nil {
					return err
				}
				if asJSON {
					enc := json.NewEncoder(cmd.OutOrStdout())
					enc.SetIndent("", "  ")
					return enc.Encode(out)
				}
				printDeliveryStatus(cmd.OutOrStdout(), out, time.Now())
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print JSON")
	return cmd
}

// loadDeliveryStatus composes the status from the store and the service.
func loadDeliveryStatus(ctx context.Context, st *store.Store, svc *deliverysvc.Service) (deliveryStatus, error) {
	var out deliveryStatus
	links, err := st.ListProviderLinks(ctx)
	if err != nil {
		return out, err
	}
	repos, err := st.ListDeliveryRepos(ctx)
	if err != nil {
		return out, err
	}
	used, capBytes, mirrors, err := svc.MirrorUsage(ctx)
	if err != nil {
		return out, err
	}
	out.UsedBytes, out.CapBytes = used, capBytes
	served := dashapi.CountServedRepos(links, repos)
	out.Links = []dashapi.APIDeliveryLink{}
	for _, l := range links {
		out.Links = append(out.Links, dashapi.DeliveryLinkWire(l, served[l.ID]))
	}
	out.Mirrors = []dashapi.APIDeliveryMirror{}
	for _, m := range mirrors {
		out.Mirrors = append(out.Mirrors, dashapi.DeliveryMirrorWire(m))
	}
	out.Projects = []deliveryProjectStatus{}
	seen := map[int64]bool{}
	for _, r := range repos {
		if seen[r.ProjectID] {
			continue
		}
		seen[r.ProjectID] = true
		root, err := st.ProjectRootByID(ctx, r.ProjectID)
		if err != nil {
			return out, err
		}
		remotes, err := st.LoadProjectRemotes(ctx, r.ProjectID)
		if err != nil {
			return out, err
		}
		ps, err := st.GetDeliveryProjectSettings(ctx, r.ProjectID)
		if err != nil {
			return out, err
		}
		view := dashapi.ComposeProjectDelivery(dashapi.ProjectDeliveryInput{
			ProjectID: r.ProjectID, Now: time.Now().UTC(), Remotes: remotes, Links: links, Mirrors: mirrors, Settings: ps,
		})
		out.Projects = append(out.Projects, deliveryProjectStatus{ProjectID: r.ProjectID, Root: root, Remotes: view.Remotes, Settings: view.Settings})
	}
	return out, nil
}

// printDeliveryStatus renders the status as plain text.
func printDeliveryStatus(w io.Writer, s deliveryStatus, now time.Time) {
	fmt.Fprintln(w, "Code hosts")
	if len(s.Links) == 0 {
		fmt.Fprintln(w, "  none connected: local git only, nothing is sent anywhere.")
		fmt.Fprintln(w, "  Connect GitHub with a fine-grained read-only token: observer delivery connect --token-stdin")
	}
	for _, l := range s.Links {
		who := l.AccountLogin
		if who != "" {
			who = "@" + who
		}
		fmt.Fprintf(w, "  #%d  %s  %s  %s  %s  last ok %s  %d repositories\n",
			l.ID, l.Host, authModeText(l.AuthMode), who, l.Status, agoText(l.LastOKAt, now), l.Repos)
		if l.LastError != "" {
			fmt.Fprintf(w, "       %s\n", l.LastError)
		}
	}
	fmt.Fprintf(w, "\nMirrors  %s used of %s cap\n", humanBytes(s.UsedBytes), capText(s.CapBytes))
	if len(s.Mirrors) == 0 {
		fmt.Fprintln(w, "  none")
	}
	for _, m := range s.Mirrors {
		fmt.Fprintf(w, "  #%d  %s  %s  %s  refreshed %s\n", m.ID, m.URL, humanBytes(m.SizeBytes), m.Status, agoText(m.LastRefreshAt, now))
		if m.LastError != "" {
			fmt.Fprintf(w, "       %s\n", m.LastError)
		}
	}
	fmt.Fprintln(w, "\nProjects with AI-touched commits in the last 90 days")
	if len(s.Projects) == 0 {
		fmt.Fprintln(w, "  none yet")
	}
	for _, p := range s.Projects {
		mirror := "off"
		if p.Settings.MirrorEnabled {
			mirror = "on, Check now only"
			if p.Settings.ScheduleMinutes > 0 {
				mirror = fmt.Sprintf("on, every %d min", p.Settings.ScheduleMinutes)
			}
		}
		fmt.Fprintf(w, "  %s (id %d)  mirror %s\n", p.Root, p.ProjectID, mirror)
		for _, r := range p.Remotes {
			slug := r.RepoSlug
			if slug == "" {
				slug = r.URL
			}
			fmt.Fprintf(w, "    %s  %s %s  source %s  last fetch %s\n", r.Name, r.Provider, slug, sourceText(r.Source), agoText(r.FetchHeadAt, now))
		}
	}
}

func authModeText(mode string) string {
	if mode == deliverynet.AuthGHCLI {
		return "gh login"
	}
	return "token"
}

func sourceText(src string) string {
	switch delivery.EvidenceSource(src) {
	case delivery.SourceProvider:
		return "code host"
	case delivery.SourceMirror:
		return "Observer mirror"
	}
	return "your own fetches"
}

func capText(capBytes int64) string {
	if capBytes <= 0 {
		return "no"
	}
	return humanBytes(capBytes)
}

// agoText renders an RFC3339 time as "4m ago", or "never".
func agoText(at string, now time.Time) string {
	t, err := time.Parse(time.RFC3339Nano, at)
	if at == "" || err != nil {
		return "never"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

func newDeliveryConnectCmd() *cobra.Command {
	var (
		host       string
		tokenStdin bool
		useGH      bool
	)
	cmd := &cobra.Command{
		Use:   "connect (--token-stdin | --gh)",
		Short: "Connect GitHub: a fine-grained read-only token (recommended) or your gh login",
		Long: `Connect GitHub so Observer can read pull request state (open, draft,
conflicts, checks, reviews, merged or closed) for repositories with
AI-touched commits. Off until you run this.

Recommended: a fine-grained personal access token, read only, limited to the
repositories you pick. Permissions: Metadata read, Pull requests read,
Contents read, Commit statuses read. It is read from stdin (never the command
line) and stored in the system keychain, never in the database:

  observer delivery connect --token-stdin < token.txt

Alternative: reuse your existing gh CLI login. Observer stores nothing, but
note that a gh login is usually a read and write token on every repository
you can reach; Observer only ever reads with it:

  observer delivery connect --gh

Observer then calls api.github.com (or your GitHub Enterprise host) only,
read only, about every [delivery].poll_minutes, with no redirects followed.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if tokenStdin == useGH {
				return errors.New("pick one: --token-stdin (recommended) or --gh")
			}
			req := deliverysvc.ConnectRequest{Provider: delivery.ProviderGitHub, Host: host, AuthMode: deliverynet.AuthGHCLI}
			if tokenStdin {
				raw, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), deliveryTokenMaxBytes))
				if err != nil {
					return fmt.Errorf("read token from stdin: %w", err)
				}
				req.AuthMode, req.Token = deliverynet.AuthToken, strings.TrimSpace(string(raw))
				if req.Token == "" {
					return errors.New("no token on stdin")
				}
			}
			return withDelivery(cmd, func(ctx context.Context, _ *store.Store, svc *deliverysvc.Service) error {
				l, err := svc.Connect(ctx, req)
				if err != nil {
					return deliveryCLIErr(err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Connected %s as @%s (%s, link #%d). PR state will appear within a few minutes; run `observer delivery check <project>` to read it now.\n",
					l.Host, l.AccountLogin, authModeText(l.AuthMode), l.ID)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", deliverynet.GitHubDotCom, "GitHub web host (github.com, or a GitHub Enterprise Server host)")
	cmd.Flags().BoolVar(&tokenStdin, "token-stdin", false, "Read a fine-grained read-only token from stdin (recommended)")
	cmd.Flags().BoolVar(&useGH, "gh", false, "Reuse your gh CLI login (usually a read and write token; Observer only reads)")
	return cmd
}

// linkIDArg parses a positive link or mirror id.
func linkIDArg(s string) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimPrefix(s, "#"), 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("%q is not an id (see `observer delivery status`)", s)
	}
	return id, nil
}

func newDeliveryTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test <link-id>",
		Short: "Test a code host connection (a stopped connection restarts when the test passes)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := linkIDArg(args[0])
			if err != nil {
				return err
			}
			return withDelivery(cmd, func(ctx context.Context, _ *store.Store, svc *deliverysvc.Service) error {
				l, err := svc.TestLink(ctx, id)
				if err != nil {
					return deliveryCLIErr(err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "#%d %s: %s\n", l.ID, l.Host, l.Status)
				if l.LastError != "" {
					fmt.Fprintln(cmd.OutOrStdout(), l.LastError)
				}
				return nil
			})
		},
	}
}

func newDeliveryDisconnectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disconnect <link-id>",
		Short: "Disconnect a code host: deletes its keychain entry and the PR data it fetched",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := linkIDArg(args[0])
			if err != nil {
				return err
			}
			return withDelivery(cmd, func(ctx context.Context, _ *store.Store, svc *deliverysvc.Service) error {
				if err := svc.Disconnect(ctx, id); err != nil {
					return deliveryCLIErr(err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Disconnected #%d. Local landing detection keeps running.\n", id)
				return nil
			})
		},
	}
}

// resolveDeliveryProject accepts a project id or a project root path.
func resolveDeliveryProject(ctx context.Context, st *store.Store, arg string) (int64, string, error) {
	if id, err := strconv.ParseInt(arg, 10, 64); err == nil && id > 0 {
		root, err := st.ProjectRootByID(ctx, id)
		if err != nil {
			return 0, "", err
		}
		if root == "" {
			return 0, "", fmt.Errorf("no project with id %d", id)
		}
		return id, root, nil
	}
	root := arg
	if abs, err := filepath.Abs(arg); err == nil {
		root = abs
	}
	id, err := st.ProjectIDForRoot(ctx, root)
	if err != nil {
		return 0, "", err
	}
	if id == 0 {
		return 0, "", fmt.Errorf("no project recorded at %s (pass a project id, see `observer delivery status`)", root)
	}
	return id, root, nil
}

func newDeliveryCheckCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "check <project-id | path>",
		Short: "Check one project now: code host calls, a mirror refresh if opted in, then the landing evaluation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withDelivery(cmd, func(ctx context.Context, st *store.Store, svc *deliverysvc.Service) error {
				id, root, err := resolveDeliveryProject(ctx, st, args[0])
				if err != nil {
					return err
				}
				res, err := svc.CheckProject(ctx, id)
				if err != nil {
					return deliveryCLIErr(err)
				}
				out := deliveryCheckWire(res)
				if asJSON {
					enc := json.NewEncoder(cmd.OutOrStdout())
					enc.SetIndent("", "  ")
					return enc.Encode(out)
				}
				w := cmd.OutOrStdout()
				fmt.Fprintf(w, "Checked %s (id %d)\n", root, id)
				if len(out.Repos) == 0 {
					fmt.Fprintln(w, "  no remote recorded yet: the commit scanner reads remotes on its next pass")
				}
				for _, r := range out.Repos {
					fmt.Fprintf(w, "  %s %s  %s  %s", r.RemoteName, r.RepoSlug, sourceText(r.Source), r.Status)
					if r.CommitsChecked > 0 || r.PRsUpserted > 0 {
						fmt.Fprintf(w, "  %d commits asked about, %d PRs updated", r.CommitsChecked, r.PRsUpserted)
					}
					fmt.Fprintln(w)
					if r.Detail != "" {
						fmt.Fprintf(w, "    %s\n", r.Detail)
					}
				}
				if !out.Reevaluated {
					fmt.Fprintln(w, "  landing evaluation did not run ([delivery].local is off, or it failed; see the daemon log)")
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print JSON")
	return cmd
}

func newDeliveryMirrorsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mirrors",
		Short: "Observer-owned mirrors under ~/.observer/delivery/mirrors",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List mirrors with their size, and the total against [delivery].mirror_cap_mb",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withDelivery(cmd, func(ctx context.Context, _ *store.Store, svc *deliverysvc.Service) error {
				used, capBytes, mirrors, err := svc.MirrorUsage(ctx)
				if err != nil {
					return err
				}
				w := cmd.OutOrStdout()
				now := time.Now()
				fmt.Fprintf(w, "%s used of %s cap\n", humanBytes(used), capText(capBytes))
				for _, m := range mirrors {
					mw := dashapi.DeliveryMirrorWire(m)
					fmt.Fprintf(w, "  #%d  %s  %s  %s  refreshed %s\n    %s\n", m.ID, m.URL, humanBytes(m.SizeBytes), mw.Status, agoText(mw.LastRefreshAt, now), m.Path)
				}
				return nil
			})
		},
	}, &cobra.Command{
		Use:   "delete <mirror-id>",
		Short: "Delete a mirror's directory and its record (re-created on the next Check now if the project still opts in)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := linkIDArg(args[0])
			if err != nil {
				return err
			}
			return withDelivery(cmd, func(ctx context.Context, _ *store.Store, svc *deliverysvc.Service) error {
				if err := svc.DeleteMirror(ctx, id); err != nil {
					return deliveryCLIErr(err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Deleted mirror #%d.\n", id)
				return nil
			})
		},
	})
	return cmd
}

func newDeliveryProjectCmd() *cobra.Command {
	var (
		mirror   string
		schedule int
	)
	cmd := &cobra.Command{
		Use:   "project <project-id | path>",
		Short: "Show or set a project's mirror opt-in and refresh schedule",
		Long: `A project whose remote has no code host connection (another host, or GitHub
not connected) can opt into an Observer-owned mirror: a bare, blobless copy
under ~/.observer/delivery/mirrors, refreshed only by "Check now" or on a
schedule of at least 30 minutes. Your own repository is never written to.

  observer delivery project 12 --mirror on --schedule 60
  observer delivery project 12 --mirror off`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withDelivery(cmd, func(ctx context.Context, st *store.Store, _ *deliverysvc.Service) error {
				id, root, err := resolveDeliveryProject(ctx, st, args[0])
				if err != nil {
					return err
				}
				ps, err := st.GetDeliveryProjectSettings(ctx, id)
				if err != nil {
					return err
				}
				changed := false
				switch strings.ToLower(mirror) {
				case "":
				case "on":
					ps.MirrorEnabled, changed = true, true
				case "off":
					ps.MirrorEnabled, ps.ScheduleMinutes, changed = false, 0, true
				default:
					return fmt.Errorf("--mirror takes on or off, not %q", mirror)
				}
				if cmd.Flags().Changed("schedule") {
					if !dashapi.ValidDeliverySchedule(schedule) {
						return fmt.Errorf("--schedule must be 0 (Check now only) or between %d minutes and one week", dashapi.DeliveryMinScheduleMinutes)
					}
					if !ps.MirrorEnabled {
						return errors.New("--schedule needs the mirror on (--mirror on)")
					}
					ps.ScheduleMinutes, changed = schedule, true
				}
				if changed {
					ps.ProjectID, ps.UpdatedAt = id, time.Now().UTC()
					if err := st.SetDeliveryProjectSettings(ctx, ps); err != nil {
						return err
					}
				}
				state := "off"
				if ps.MirrorEnabled {
					state = "on, Check now only"
					if ps.ScheduleMinutes > 0 {
						state = fmt.Sprintf("on, refreshed every %d minutes", ps.ScheduleMinutes)
					}
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s (id %d): mirror %s\n", root, id, state)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&mirror, "mirror", "", "on or off")
	cmd.Flags().IntVar(&schedule, "schedule", 0, "Refresh every N minutes (0 = Check now only, else at least 30)")
	return cmd
}
