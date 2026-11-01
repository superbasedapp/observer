package opencode

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// storeFileRE matches the database file names OpenCode writes. Upstream
// (anomalyco/opencode packages/cli/src/database-path.ts, databasePath, at
// commit 7fb79388a) names the store opencode.db for the latest, dev,
// beta, next and prod channels (or when OPENCODE_DISABLE_CHANNEL_DB is
// set) and opencode-<channel>.db for every other channel, the channel
// sanitized with /[^a-zA-Z0-9._-]/g -> "-". So a stable or local build
// keeps its sessions in, for example, opencode-stable.db or
// opencode-local.db beside (or instead of) opencode.db. The five default
// channels never produce opencode-<channel>.db, so those names are not
// claimed. An OPENCODE_DB override can name any file; that one is not
// discoverable by name.
var storeFileRE = regexp.MustCompile(`(?i)^opencode(-([a-z0-9._-]+))?\.db$`)

// defaultChannels are the channels upstream maps to plain opencode.db.
var defaultChannels = map[string]bool{"latest": true, "dev": true, "beta": true, "next": true, "prod": true}

// isStoreDBName reports whether base is a database file name OpenCode
// writes (opencode.db, or opencode-<channel>.db for a non-default
// channel).
func isStoreDBName(base string) bool {
	m := storeFileRE.FindStringSubmatch(base)
	if m == nil {
		return false
	}
	return !defaultChannels[strings.ToLower(m[2])]
}

// splitWALSibling strips a -wal or -shm suffix from base, reporting
// which (if any) was present.
func splitWALSibling(base string) (db, suffix string) {
	lower := strings.ToLower(base)
	for _, s := range []string{"-wal", "-shm"} {
		if strings.HasSuffix(lower, s) {
			return base[:len(base)-len(s)], s
		}
	}
	return base, ""
}

// channelStoresIn returns the OpenCode databases directly under dir:
// opencode.db first, then every opencode-<channel>.db in name order.
func channelStoresIn(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var primary string
	var channels []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !isStoreDBName(name) {
			continue
		}
		if strings.EqualFold(name, "opencode.db") {
			primary = filepath.Join(dir, name)
			continue
		}
		channels = append(channels, filepath.Join(dir, name))
	}
	sort.Strings(channels)
	if primary != "" {
		return append([]string{primary}, channels...)
	}
	return channels
}
