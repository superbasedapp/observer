package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// Managed-node stale disable strip (2026-11-12 operator ruling: stale entries
// of an older build do not persist). On a managed node the guard ignores a
// `[guard.rules] disable` entry for any built-in rule (internal/guard
// managedlock.go); the daemon removes such entries from the node's own
// config file, at start beside the config auto-migration (MigrateFile) and
// again whenever a policy-state report finds one, so the file says what the
// node runs. The ids to remove are decided by the caller from the live
// guard; this file only edits the text.

// guardRulesDisablePath is the TOML path of the `[guard.rules] disable` list.
var guardRulesDisablePath = []string{"guard", "rules", "disable"}

// GuardStripBackupSuffix is the suffix of the backup the strip writes beside
// the config file (config.toml.guard-strip.bak). It is its own name so the
// strip never overwrites the config.toml.bak the same start's auto-migration
// (or a dashboard save) may just have written.
const GuardStripBackupSuffix = ".guard-strip.bak"

// GuardStripBackupPath is the backup the strip writes for the config file at
// path.
func GuardStripBackupPath(path string) string { return path + GuardStripBackupSuffix }

// RemoveGuardRuleDisables removes the ids in drop from the `[guard.rules]
// disable` list of the config file at path, key by key so every comment and
// untouched line survives, through the shared atomic writer (the prior file
// lands in GuardStripBackupPath(path)). The whole read-patch-write span holds
// the process-wide config lock (WithConfigLock), so a dashboard save in the
// same process can neither be overwritten nor overwrite the strip. It
// returns the ids it removed, in the file's order; an id the file does not
// list is not an error. A missing file, a file with no such list, or a drop
// set the list does not hold changes nothing. A file the key-by-key editor
// cannot change safely is left untouched and reported as an error: the
// strip never re-serializes the operator's file.
func RemoveGuardRuleDisables(path string, drop []string) ([]string, error) {
	if path == "" {
		return nil, errors.New("config.RemoveGuardRuleDisables: empty path")
	}
	if len(drop) == 0 {
		return nil, nil
	}
	var removed []string
	err := WithConfigLock(func() error {
		var err error
		removed, err = removeGuardRuleDisablesLocked(path, drop)
		return err
	})
	return removed, err
}

// removeGuardRuleDisablesLocked is RemoveGuardRuleDisables's body, run under
// the config lock.
func removeGuardRuleDisablesLocked(path string, drop []string) ([]string, error) {
	current, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("config.RemoveGuardRuleDisables: read %s: %w", path, err)
	}
	tree, err := decodeTree(string(current))
	if err != nil {
		return nil, fmt.Errorf("config.RemoveGuardRuleDisables: decode %s: %w", path, err)
	}
	list, ok := treeList(tree, guardRulesDisablePath)
	if !ok {
		return nil, nil
	}
	dropSet := map[string]bool{}
	for _, id := range drop {
		dropSet[strings.TrimSpace(id)] = true
	}
	var removed []string
	kept := make([]any, 0, len(list))
	for _, v := range list {
		s, isStr := v.(string)
		if isStr && dropSet[strings.TrimSpace(s)] {
			removed = append(removed, strings.TrimSpace(s))
			continue
		}
		kept = append(kept, v)
	}
	if len(removed) == 0 {
		return nil, nil
	}
	patch := Patch{Path: guardRulesDisablePath, Dotted: "guard.rules.disable", Value: kept}
	if len(kept) == 0 {
		patch = Patch{Path: guardRulesDisablePath, Dotted: "guard.rules.disable", Delete: true}
	}
	text, reason, ok := structuralText(string(current), []Patch{patch})
	if !ok {
		return nil, fmt.Errorf("config.RemoveGuardRuleDisables: %s: %s", path, reason)
	}
	if err := writeBytesAtomicBackup(path, []byte(text), GuardStripBackupPath(path)); err != nil {
		return nil, fmt.Errorf("config.RemoveGuardRuleDisables: write %s: %w", path, err)
	}
	return removed, nil
}

// treeList returns the list at path in a decoded TOML tree.
func treeList(tree map[string]any, path []string) ([]any, bool) {
	cur := tree
	for i, seg := range path {
		v, ok := cur[seg]
		if !ok {
			return nil, false
		}
		if i == len(path)-1 {
			list, ok := v.([]any)
			return list, ok
		}
		next, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return nil, false
}
