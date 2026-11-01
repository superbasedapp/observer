//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
	"github.com/marmutapp/superbased-observer/internal/policyfam/terminalsisolation"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// sandbox_floors_source.go is the one reader of the organization's
// isolation floors for a re-adoption or a restore (R-035, the GATES-SBX
// merge's note that a CLI process never saw them). In the daemon the floors
// it installed are in memory (sandboxOrgFloors); a CLI process reads the
// same verified, durable-state-matched terminals.isolation cache the daemon
// installed from (loadPolicyResourceFromCache), so `observer sandbox
// readopt`, `restore` and the dashboard's route judge against the same
// floors.

// errOrgFloorsUnreadable is the named reason a CLI re-adoption or restore
// is refused when it cannot tell which organization isolation floors are in
// force (R-166, LEFT2-SBX audit finding 8): it fails closed, as the daemon
// route does, instead of judging against no floor.
var errOrgFloorsUnreadable = errors.New("org_floors_unreadable: the organization's isolation floors could not be read")

// sandboxOrgFloorsFor returns the floors in force for this process. In a
// CLI process an error means a floor may be in force that could not be
// read; the caller refuses (fails closed) rather than judge against none.
func sandboxOrgFloorsFor(ctx context.Context, cfg config.Config) (sandboxselect.Floors, error) {
	if policyResourceInstalledHere.Load() {
		return sandboxOrgFloors(), nil
	}
	spec, ok, err := sandboxCachedIsolationSpec(ctx, cfg)
	if err != nil {
		return sandboxselect.Floors{}, err
	}
	return sandboxFloorsFromSpec(spec, ok), nil
}

// sandboxCachedIsolationSpec reads the terminals.isolation spec a CLI
// process sees: the verified cache when it is applied and not inert. ok
// false with a nil error is "no floor in force" (not enrolled, the family
// not accepted, nothing recorded, a verified withdrawal, an inert body);
// an error is "a floor may be in force and could not be read".
var sandboxCachedIsolationSpec = func(ctx context.Context, cfg config.Config) (terminalsisolation.PolicySpec, bool, error) {
	st, cleanup, err := openSandboxManagedStore(ctx, cfg)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return terminalsisolation.PolicySpec{}, false, nil // no database: never enrolled
		}
		return terminalsisolation.PolicySpec{}, false, fmt.Errorf("%w: open the database: %w", errOrgFloorsUnreadable, err)
	}
	defer cleanup()
	raw, inert, ok := loadPolicyResourceFromCache(ctx, cfg, st, policyfam.FamilyTerminalsIsolation)
	if ok {
		return isolationSpecFromCache(raw, inert)
	}
	if err := isolationFloorUnread(ctx, cfg, st); err != nil {
		return terminalsisolation.PolicySpec{}, false, err
	}
	return terminalsisolation.PolicySpec{}, false, nil
}

// isolationSpecFromCache reads a body the cache applied: an inert body or
// one with no floor in force is "no floor"; a body that does not decode to
// the family's spec is a broken cache, so a floor may be in force that this
// process cannot read (errOrgFloorsUnreadable, audit F3 of the RBFIX lane).
func isolationSpecFromCache(raw any, inert string) (terminalsisolation.PolicySpec, bool, error) {
	spec, isSpec := raw.(terminalsisolation.PolicySpec)
	if !isSpec {
		return terminalsisolation.PolicySpec{}, false, fmt.Errorf("%w: the cached %s body decodes to %T, not its spec", errOrgFloorsUnreadable, policyfam.FamilyTerminalsIsolation, raw)
	}
	if inert != "" || !spec.InForce() {
		return terminalsisolation.PolicySpec{}, false, nil
	}
	return spec, true, nil
}

// sandboxFloorCacheStat is os.Stat; a test replaces it to model a cache
// folder that cannot be checked.
var sandboxFloorCacheStat = os.Stat

// isolationFloorUnread tells the two reasons loadPolicyResourceFromCache
// applies nothing apart: no floor is recorded for this enrolment (nil), or
// one is recorded and its cached body does not verify against the durable
// state, so this process cannot know it (errOrgFloorsUnreadable). The daemon
// in the second case refetches; a CLI never fetches, so it refuses. A
// signed withdrawal whose message is the recorded one is "no floor".
func isolationFloorUnread(ctx context.Context, cfg config.Config, st *store.Store) error {
	family := policyfam.FamilyTerminalsIsolation
	unread := func(why string, a ...any) error {
		return fmt.Errorf("%w: %s", errOrgFloorsUnreadable, fmt.Sprintf(why, a...))
	}
	enr, err := st.LoadEnrolment(ctx)
	if err != nil {
		return unread("read the enrolment: %v", err)
	}
	if enr == nil {
		return nil
	}
	orgKey := orgclient.OrgKey(enr.OrgServerURL, enr.OrgID)
	genRow, has, err := st.LoadEnrolmentGeneration(ctx, orgKey)
	if err != nil {
		return unread("read the enrolment generation: %v", err)
	}
	if !has || genRow.Tombstoned {
		return nil
	}
	opts := policyResourceOptionsFor(cfg, nodeLiveCapabilitiesFor(nil, componentSnapshotForConfig(cfg).ModuleActive))
	if !containsString(family, opts.AcceptFamilies) {
		return nil
	}
	row, hasState, err := st.LoadPolicyResourceState(ctx, orgKey, family)
	if err != nil {
		return unread("read the recorded floor: %v", err)
	}
	cachePath := filepath.Join(opts.CacheDir, orgKey, strconv.FormatInt(genRow.Generation, 10), family+".json")
	if !hasState || row.Generation != genRow.Generation {
		// Nothing recorded for this enrolment. A cached body with no
		// recorded floor is one the daemon would install at its next start.
		_, statErr := sandboxFloorCacheStat(cachePath)
		switch {
		case statErr == nil:
			return unread("a cached floor is not yet recorded; start the daemon once so it installs it")
		case !errors.Is(statErr, fs.ErrNotExist):
			// The cache cannot be checked (for example no permission on
			// its folder): a floor may be waiting there.
			return unread("the floor cache cannot be checked: %v", statErr)
		}
		return nil
	}
	if rawCache, readErr := os.ReadFile(cachePath); readErr == nil {
		var resource orgcontract.SignedPolicyResource
		if json.Unmarshal(rawCache, &resource) == nil && orgcontract.IsPolicyResourceTombstone(resource) {
			if digest, dErr := orgcontract.PolicyResourceMessageDigest(resource); dErr == nil &&
				resource.Version == row.FloorVersion && digest == row.MsgDigest {
				return nil // the recorded withdrawal: no floor
			}
		}
	}
	cached, err := verifyCachedPolicyResource(ctx, st, enr.OrgServerURL, family, cachePath, opts.NodeAttrs)
	if err != nil {
		return unread("floor version %d is recorded but its cached body does not verify: %v", row.FloorVersion, err)
	}
	if cached.resource.Version != row.FloorVersion || cached.digest != row.MsgDigest {
		return unread("floor version %d is recorded but the cached body is version %d", row.FloorVersion, cached.resource.Version)
	}
	// The cache matches the record: loadPolicyResourceFromCache applied
	// nothing for a reason the daemon shares (a capability this node does
	// not advertise), so no floor applies here either.
	return nil
}
