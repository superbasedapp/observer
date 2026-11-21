package secassess

import (
	"strings"
	"testing"
)

// TestEffectiveSecretMode: one row per row of the words table and per way the
// setting meets the machine.
func TestEffectiveSecretMode(t *testing.T) {
	cases := []struct {
		name       string
		in         SecretModeInput
		effective  string
		refuse     bool
		unreadable bool
		downgraded bool
		wordsHave  string // "" means no words
		tier       bool
	}{
		{"off says nothing", SecretModeInput{Configured: SecretOff, EnvFiles: 3, Tier: "proxy_only"}, SecretOff, false, false, false, "", false},
		{"off under a wider tier still says nothing", SecretModeInput{Configured: SecretOff, EnvFiles: 3, Tier: "internet"}, SecretOff, false, false, false, "", false},
		{"warn with files", SecretModeInput{Configured: SecretWarn, EnvFiles: 2, Tier: "proxy_only"}, SecretWarn, false, false, false, "2 environment files are at the top level of this folder (nested ones are not counted)", false},
		{"warn with one file", SecretModeInput{Configured: SecretWarn, EnvFiles: 1, Tier: "proxy_only"}, SecretWarn, false, false, false, "1 environment file is at the top level of this folder", false},
		{"warn with none", SecretModeInput{Configured: SecretWarn, Tier: "proxy_only"}, SecretWarn, false, false, false, "", false},
		{"mask where the box can mask", SecretModeInput{Configured: SecretMask, EnvFiles: 2, Mask: MaskCan, Tier: "proxy_only"}, SecretMask, false, false, false, "asks the sandbox to hide environment and key files", false},
		{"mask where the box can mask names the count", SecretModeInput{Configured: SecretMask, EnvFiles: 1, Mask: MaskCan, Tier: "proxy_only"}, SecretMask, false, false, false, "1 environment file is at the top level of this folder", false},
		{"mask where the box can mask, no files, still says what it does", SecretModeInput{Configured: SecretMask, Mask: MaskCan, Tier: "proxy_only"}, SecretMask, false, false, false, "a snapshot taken when the box starts", false},
		{"mask where the sandbox cannot acts as a warning", SecretModeInput{Configured: SecretMask, EnvFiles: 2, Mask: MaskCannot, Tier: "proxy_only"}, SecretWarn, false, false, true, "the sandbox this run will use cannot hide files, so it acts as a warning", false},
		{"mask with no sandbox chosen acts as a warning", SecretModeInput{Configured: SecretMask, EnvFiles: 2, Tier: "proxy_only"}, SecretWarn, false, false, true, "no sandbox is chosen for this run yet, so it acts as a warning", false},
		{"mask where the launcher cannot report acts as a warning", SecretModeInput{Configured: SecretMask, EnvFiles: 2, Mask: MaskNoReport, Tier: "proxy_only"}, SecretWarn, false, false, true, "launcher cannot report what the mask hid, and a mask nobody can check is not asked for, so it acts as a warning", false},
		{"mask where it cannot, no files", SecretModeInput{Configured: SecretMask, Mask: MaskCannot, Tier: "proxy_only"}, SecretWarn, false, false, true, "", false},
		{"warn is not changed by a sandbox that can mask", SecretModeInput{Configured: SecretWarn, EnvFiles: 2, Mask: MaskCan, Tier: "proxy_only"}, SecretWarn, false, false, false, "2 environment files are at the top level", false},
		{"mask under a wider tier keeps the consent line", SecretModeInput{Configured: SecretMask, EnvFiles: 1, Mask: MaskCan, Tier: "internet"}, SecretMask, false, false, false, "snapshot", true},
		{"refuse with an open secret", SecretModeInput{Configured: SecretRefuse, EnvFiles: 1, OpenSecret: true, Scan: ScanDone, LastScan: "2026-11-12", Tier: "proxy_only"}, SecretRefuse, true, false, false, "still open", false},
		{"refuse with an open secret and no env file (a key file)", SecretModeInput{Configured: SecretRefuse, OpenSecret: true, Tier: "proxy_only"}, SecretRefuse, true, false, false, "still open", false},
		{"refuse when the findings cannot be read", SecretModeInput{Configured: SecretRefuse, FindingsUnreadable: true, Tier: "proxy_only"}, SecretRefuse, true, true, false, "could not read its findings", false},
		{"refuse with an open secret AND unreadable names the open secret", SecretModeInput{Configured: SecretRefuse, OpenSecret: true, FindingsUnreadable: true}, SecretRefuse, true, false, false, "still open", false},
		{"refuse armed, scanned", SecretModeInput{Configured: SecretRefuse, EnvFiles: 2, Scan: ScanDone, LastScan: "2026-11-12", Tier: "proxy_only"}, SecretRefuse, false, false, false, "last scanned 2026-11-12", false},
		{"refuse armed, never scanned says what is known", SecretModeInput{Configured: SecretRefuse, EnvFiles: 2, Scan: ScanNever, Tier: "proxy_only"}, SecretRefuse, false, false, false, "never scanned this project", false},
		{"refuse armed, scan unasked", SecretModeInput{Configured: SecretRefuse, Tier: "proxy_only"}, SecretRefuse, false, false, false, "hold no open secret in an environment or key file.", false},
		{"an unknown setting reads as warn", SecretModeInput{Configured: "hide", EnvFiles: 1, Tier: "proxy_only"}, SecretWarn, false, false, false, "1 environment file is", false},
		{"a wider tier adds the consent line", SecretModeInput{Configured: SecretWarn, EnvFiles: 1, Tier: "internet"}, SecretWarn, false, false, false, "readable inside the box", true},
		{"a wider tier adds the consent line with no top-level file (a nested file is as readable)", SecretModeInput{Configured: SecretWarn, Tier: "internet"}, SecretWarn, false, false, false, "", true},
		{"a wider tier under refuse adds it too", SecretModeInput{Configured: SecretRefuse, Scan: ScanDone, LastScan: "2026-11-12", Tier: "internet"}, SecretRefuse, false, false, false, "last scanned", true},
		{"the proxy-only tier adds none", SecretModeInput{Configured: SecretWarn, EnvFiles: 1, Tier: "proxy_only"}, SecretWarn, false, false, false, "1 environment file", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EffectiveSecretMode(tc.in)
			if got.Effective != tc.effective || got.Refuse != tc.refuse || got.Unreadable != tc.unreadable || got.Downgraded != tc.downgraded {
				t.Fatalf("effective %q refuse %v unreadable %v downgraded %v; want %q %v %v %v", got.Effective, got.Refuse, got.Unreadable, got.Downgraded, tc.effective, tc.refuse, tc.unreadable, tc.downgraded)
			}
			if tc.wordsHave == "" && got.Words != "" {
				t.Errorf("words %q, want none", got.Words)
			}
			if tc.wordsHave != "" && !strings.Contains(got.Words, tc.wordsHave) {
				t.Errorf("words %q lack %q", got.Words, tc.wordsHave)
			}
			if (got.TierWords != "") != tc.tier {
				t.Errorf("tier words %q, want present %v", got.TierWords, tc.tier)
			}
			for _, bad := range []string{"safe", "secure", "verified", "confirmed", "none is open now"} {
				if strings.Contains(strings.ToLower(got.Words+got.TierWords), bad) {
					t.Errorf("words claim %q", bad)
				}
			}
		})
	}
}

// TestSecretModeEffectiveForEveryMode pins what each configured value resolves
// to for every capability of the run's sandbox (decision D32): the value in force
// is what a launch row and a run record must carry, so mask is "mask" only when
// the sandbox can hide files and the launcher can report what it hid, and "warn"
// for every other capability, with the closed reason.
func TestSecretModeEffectiveForEveryMode(t *testing.T) {
	for _, c := range []struct {
		configured string
		mask       MaskCapability
		want       string
		why        string
	}{
		{SecretOff, MaskNoBackend, SecretOff, ""},
		{SecretOff, MaskCan, SecretOff, ""},
		{SecretWarn, MaskNoBackend, SecretWarn, ""},
		{SecretWarn, MaskCan, SecretWarn, ""},
		{SecretMask, MaskNoBackend, SecretWarn, "no_backend"},
		{SecretMask, MaskCannot, SecretWarn, "backend_cannot_mask"},
		{SecretMask, MaskNoReport, SecretWarn, "launcher_cannot_report"},
		{SecretMask, MaskCan, SecretMask, ""},
		{SecretRefuse, MaskNoBackend, SecretRefuse, ""},
		{SecretRefuse, MaskCan, SecretRefuse, ""},
		{"", MaskCan, SecretWarn, ""},
		{"hide", MaskCannot, SecretWarn, ""},
	} {
		got := EffectiveSecretMode(SecretModeInput{Configured: c.configured, Mask: c.mask})
		if got.Effective != c.want || got.Why != c.why || got.Downgraded != (c.why != "") {
			t.Errorf("configured %q (mask %q): effective %q why %q downgraded %v, want %q %q", c.configured, c.mask, got.Effective, got.Why, got.Downgraded, c.want, c.why)
		}
	}
}

// TestMaskCapabilityOf: the capability is read from the probe's facts for the
// backend id by its flag, never by its name, and an unknown or empty id is
// "no backend".
func TestMaskCapabilityOf(t *testing.T) {
	facts := []BackendFact{
		{ID: "row-a", MasksSecrets: true},
		{ID: "row-b"},
	}
	for _, c := range []struct {
		name     string
		backends []BackendFact
		id       string
		reports  bool
		want     MaskCapability
	}{
		{"a row that can, with a launcher that reports", facts, "row-a", true, MaskCan},
		{"a row that can, with a launcher that does not", facts, "row-a", false, MaskNoReport},
		{"a row that cannot", facts, "row-b", true, MaskCannot},
		{"a row that cannot, launcher irrelevant", facts, "row-b", false, MaskCannot},
		{"an id the probe does not list", facts, "row-c", true, MaskNoBackend},
		{"no id", facts, "", true, MaskNoBackend},
		{"no facts", nil, "row-a", true, MaskNoBackend},
	} {
		if got := MaskCapabilityOf(c.backends, c.id, c.reports); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// TestMaskDowngradeTable: one row per capability short of MaskCan, each with a
// distinct closed word and a clause, MaskCan is none, and the words round-trip.
func TestMaskDowngradeTable(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range []MaskCapability{MaskNoBackend, MaskCannot, MaskNoReport} {
		why, down := MaskDowngradeWhy(c)
		if !down || why == "" || seen[why] {
			t.Errorf("capability %q: why %q downgraded %v (repeated: %v)", c, why, down, seen[why])
		}
		seen[why] = true
		if MaskDowngradeWords(why) == "" {
			t.Errorf("reason %q has no clause", why)
		}
	}
	if why, down := MaskDowngradeWhy(MaskCan); down || why != "" {
		t.Errorf("MaskCan reads as a downgrade: %q", why)
	}
	if MaskDowngradeWords("not_a_reason") != "" || MaskDowngradeWords("") != "" {
		t.Error("an unknown reason has words")
	}
	if len(maskDowngrades) != 3 {
		t.Errorf("%d downgrade rows, want 3 (one per capability short of can)", len(maskDowngrades))
	}
}
