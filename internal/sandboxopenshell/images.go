package sandboxopenshell

import (
	"encoding/json"
	"strconv"
	"strings"
)

// images.go pins OpenShell's two runtime images by digest (ledger row
// OSH-48, adversarial row A12). Every box of a gateway starts from its
// supervisor image and carries the sandbox binary its sandbox runtime
// image holds; the runtime canary (probe row P8) runs in the supervisor
// image. Taken by tag, a tampered or re-pushed image under the same tag
// would be used as is. Grounded on OpenShell v0.1.6 (tag ac7f615cd,
// crates/openshell-driver-docker/src/lib.rs and
// crates/openshell-core/src/{config.rs,driver_utils.rs}):
//
//   - the Docker driver reads [openshell.drivers.docker] supervisor_image
//     and sandbox_runtime_image, else the variables
//     OPENSHELL_SUPERVISOR_IMAGE and OPENSHELL_SANDBOX_RUNTIME_IMAGE, else
//     the compiled defaults ghcr.io/nvidia/openshell/supervisor:<version>
//     and ghcr.io/nvidia/openshell/sandbox:<version>;
//   - a digest-pinned reference (repo@sha256:...) is taken as an exact,
//     immutable image: pulled once when absent, never refreshed.
//
// The managed gateway is written with the digest references
// (PinnedRuntimeImages). For either gateway mode, probe row P8i inspects
// the image each reference names on the engine and requires one of its
// recorded registry digests to be a pinned one; otherwise the row is
// refused with a closed reason (ImageVerdict). A refusal, not an
// "untested" label: an image that is not the one a receipt ran is not the
// tested version, whatever its tag says, and the version table already
// refuses untested versions.

// SandboxImageRepo is the repository of OpenShell's sandbox runtime image.
const SandboxImageRepo = "ghcr.io/nvidia/openshell/sandbox"

// The runtime image roles.
const (
	// ImageSupervisor is the supervisor image (the driver's
	// supervisor_image; the canary's image).
	ImageSupervisor = "supervisor"
	// ImageSandbox is the sandbox runtime image (the driver's
	// sandbox_runtime_image).
	ImageSandbox = "sandbox"
)

// ImageRoles is the order the roles are checked and named in.
var ImageRoles = []string{ImageSupervisor, ImageSandbox}

// ImageDigests are the registry digests a tested image may carry: the
// multi-platform index digest (what a pull by tag or by the index digest
// records) and each platform manifest's digest (what an engine that pulled
// one platform by its own digest records). Every digest is
// "sha256:<64 lower hex>".
type ImageDigests struct {
	Index     string
	Platforms []string
}

// all returns the index digest and the platform digests.
func (d ImageDigests) all() []string {
	if d.Index == "" {
		return nil
	}
	return append([]string{d.Index}, d.Platforms...)
}

// pinned reports whether d names a well-formed index digest (the managed
// config's reference) and only well-formed platform digests.
func (d ImageDigests) pinned() bool {
	if !validDigest(d.Index) {
		return false
	}
	for _, p := range d.Platforms {
		if !validDigest(p) {
			return false
		}
	}
	return true
}

// validDigest reports whether s is "sha256:" and 64 lower-case hex digits.
func validDigest(s string) bool {
	h, ok := strings.CutPrefix(s, "sha256:")
	if !ok || len(h) != 64 {
		return false
	}
	return strings.Trim(h, "0123456789abcdef") == ""
}

// RuntimeImages names one image reference per role ("" for none).
type RuntimeImages struct {
	Supervisor string
	Sandbox    string
	// SandboxFromBin: the gateway's config sets supervisor_bin, so the
	// driver loads the sandbox binary from that host file and never uses
	// the sandbox runtime image (v0.1.6 DockerComputeDriver::new; audit
	// finding FU7-A10). Row P8i then does not check that role, and that
	// binary is not checked by digest.
	SandboxFromBin bool
}

// Ref returns the reference of role (ImageSupervisor or ImageSandbox).
func (r RuntimeImages) Ref(role string) string {
	if role == ImageSupervisor {
		return r.Supervisor
	}
	return r.Sandbox
}

// tag renders v as the images' tag (the bare MAJOR.MINOR.PATCH).
func tag(v Version) string {
	return Version{Major: v.Major, Minor: v.Minor, Patch: v.Patch}.String()
}

// DefaultRuntimeImages are the references a gateway of version v uses when
// its config and environment name none (the compiled defaults).
func DefaultRuntimeImages(v Version) RuntimeImages {
	return RuntimeImages{Supervisor: CanaryImageRepo + ":" + tag(v), Sandbox: SandboxImageRepo + ":" + tag(v)}
}

// EffectiveRuntimeImages is what a gateway of version v whose config names
// configured uses: each configured reference, else the default. The
// variables OPENSHELL_SUPERVISOR_IMAGE and OPENSHELL_SANDBOX_RUNTIME_IMAGE
// of a gateway Observer does not run are not visible to it, so an external
// gateway that sets them with no config key is checked against the
// default reference (ledger row OSH-48, the residual).
func EffectiveRuntimeImages(configured RuntimeImages, v Version) RuntimeImages {
	out := DefaultRuntimeImages(v)
	if s := strings.TrimSpace(configured.Supervisor); s != "" {
		out.Supervisor = s
	}
	if s := strings.TrimSpace(configured.Sandbox); s != "" {
		out.Sandbox = s
	}
	out.SandboxFromBin = configured.SandboxFromBin
	return out
}

// ImageTagNote is probe row P8i's note on images the gateway names by tag
// ("" when every image it uses is named by digest; audit finding FU7-A4).
// v0.1.6's Docker driver resolves each runtime image to an image ID once,
// at the gateway's own start (ensure_runtime_image: a versioned tag is
// pulled only when absent and never refreshed), and every box starts from
// that ID. So for a tag, row P8i checks the image the tag names on the
// engine now, not necessarily the one the running gateway resolved at its
// start; a digest reference closes that gap. A note, never a refusal: an
// external gateway's config is the user's. driver is the gateway's compute
// driver, whose config table the note names (audit FU9-A3).
func ImageTagNote(images RuntimeImages, row TestedVersion, driver string) string {
	var tags []string
	for _, role := range ImageRoles {
		if role == ImageSandbox && images.SandboxFromBin {
			continue
		}
		if ref := images.Ref(role); !digestRef(ref) {
			tags = append(tags, configKey(role)+" = "+strconv.Quote(repoOf(ref)+"@"+row.digestsFor(role).Index))
		}
	}
	note := ""
	if len(tags) > 0 {
		note = "the gateway names its runtime images by tag, which it resolved to an image once at its own start, so the digest check reads what the tag names now, not what the running gateway resolved; pin them in the gateway's " + driverConfigTable(driver) + " (" + strings.Join(tags, ", ") + ") and restart it"
	}
	if images.SandboxFromBin {
		if note != "" {
			note += "; "
		}
		note += "the gateway's config sets supervisor_bin, so its sandbox binary comes from that host file, which the digest check does not cover"
	}
	return note
}

// repoOf is an image reference without its tag or digest.
func repoOf(ref string) string {
	if i := strings.LastIndexByte(ref, '@'); i >= 0 {
		return ref[:i]
	}
	if i := strings.LastIndexByte(ref, ':'); i > strings.LastIndexByte(ref, '/') {
		return ref[:i]
	}
	return ref
}

// PinnedRuntimeImages are the digest references the managed gateway's
// config is written with for version v: the default repositories at the
// tested row's index digests. ok is false when v is not tested or a role
// has no pinned digest; the config then names no image (the driver's
// defaults) and probe row P8i refuses.
func PinnedRuntimeImages(v Version) (RuntimeImages, bool) {
	row, ok := testedRow(v)
	if !ok || !row.Supervisor.pinned() || !row.Sandbox.pinned() {
		return RuntimeImages{}, false
	}
	return RuntimeImages{
		Supervisor: CanaryImageRepo + "@" + row.Supervisor.Index,
		Sandbox:    SandboxImageRepo + "@" + row.Sandbox.Index,
	}, true
}

// digestsFor returns the tested row's digests of role.
func (t TestedVersion) digestsFor(role string) ImageDigests {
	if role == ImageSupervisor {
		return t.Supervisor
	}
	return t.Sandbox
}

// validImageRef reports whether ref is an image reference a TOML string,
// a docker argv and a reason can carry: non-empty, not a flag, printable
// ASCII with no space or quoting character.
func validImageRef(ref string) bool {
	if ref == "" || strings.HasPrefix(ref, "-") || len(ref) > 512 {
		return false
	}
	for i := 0; i < len(ref); i++ {
		if c := ref[i]; c < 0x21 || c > 0x7e || strings.IndexByte("\"'\\`$;,", c) >= 0 {
			return false
		}
	}
	return true
}

// digestRef reports whether ref is a carriable reference pinned by a
// sha256 digest (repo@sha256:<64 hex>).
func digestRef(ref string) bool {
	i := strings.LastIndexByte(ref, '@')
	return i > 0 && validImageRef(ref) && validDigest(ref[i+1:])
}

// ImageInspectArgv is the docker argv (without the program) that reads the
// registry digests the engine recorded for ref; ok is false for a
// reference the argv cannot carry.
func ImageInspectArgv(ref string) ([]string, bool) {
	if !validImageRef(ref) {
		return nil, false
	}
	return []string{"image", "inspect", "--format", "{{json .RepoDigests}}", ref}, true
}

// ImageFact is what the probe read about one role's image.
type ImageFact struct {
	// Role is ImageSupervisor or ImageSandbox.
	Role string
	// Ref is the reference the gateway uses for it.
	Ref string
	// Read: the engine answered for the reference (Missing or RepoDigests
	// is set). false: the docker call failed in another way, or the
	// reference could not be asked about.
	Read bool
	// Missing: the engine holds no image under the reference.
	Missing bool
	// RepoDigests is the engine's RepoDigests of the image
	// ("repo@sha256:...").
	RepoDigests []string
	// Detail is the first line of docker's error output when not read.
	Detail string
	// NotUsed: the gateway does not use this image (the sandbox role with
	// supervisor_bin set, RuntimeImages.SandboxFromBin), so row P8i skips
	// it.
	NotUsed bool
}

// imageMissingTexts are the docker CLI's answers for a reference the
// engine does not hold (Docker 29: "Error response from daemon: No such
// image: ..."; older: "Error: No such object: ...").
var imageMissingTexts = []string{"no such image", "no such object"}

// ClassifyImageInspect reads one `docker image inspect --format '{{json
// .RepoDigests}}' REF` answer. started is false when docker itself did not
// start or did not finish.
func ClassifyImageInspect(role, ref string, started bool, exitCode int, stdout, stderr string) ImageFact {
	f := ImageFact{Role: role, Ref: ref}
	if !started {
		f.Detail = "the docker CLI did not answer"
		return f
	}
	if exitCode != 0 {
		low := strings.ToLower(stderr)
		for _, s := range imageMissingTexts {
			if strings.Contains(low, s) {
				f.Read, f.Missing = true, true
				return f
			}
		}
		f.Detail = canaryDetail(stderr)
		return f
	}
	var ds []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &ds); err != nil {
		f.Detail = "docker's answer is not a digest list"
		return f
	}
	f.Read, f.RepoDigests = true, ds
	return f
}

// The image verdicts (probe row P8i).
const (
	// VerdictImageUnpinned: the tested row has no pinned digest for a role.
	VerdictImageUnpinned = "runtime_image_unpinned"
	// VerdictImageUnread: the engine could not be asked about an image.
	VerdictImageUnread = "runtime_image_unread"
	// VerdictImageMissing: the engine holds no image under the reference.
	VerdictImageMissing = "runtime_image_missing"
	// VerdictImageDigestMismatch: the image under the reference carries no
	// pinned digest (a re-pushed, rebuilt, retagged or tampered image).
	VerdictImageDigestMismatch = "runtime_image_digest_mismatch"
)

// imageRule is one row of the image table, walked top-down per role.
type imageRule struct {
	verdict string
	fails   func(f ImageFact, d ImageDigests) bool
	reason  func(f ImageFact, d ImageDigests, v Version, driver string) string
}

// imageRules is probe row P8i's table: per role, the first failing row
// wins.
var imageRules = []imageRule{
	{VerdictImageUnpinned, func(_ ImageFact, d ImageDigests) bool { return !d.pinned() }, func(f ImageFact, _ ImageDigests, v Version, _ string) string {
		return "OpenShell " + v.String() + " has no pinned digest for its " + roleName(f.Role) + " in Observer's tested-version table, so its image cannot be checked"
	}},
	{VerdictImageUnread, func(f ImageFact, _ ImageDigests) bool { return !f.Read }, func(f ImageFact, _ ImageDigests, _ Version, _ string) string {
		return "could not read the registry digests of the gateway's " + roleName(f.Role) + " " + quoteOr(f.Ref, "(no reference)") + " from the container engine" + detailSuffix(f.Detail)
	}},
	{VerdictImageMissing, func(f ImageFact, _ ImageDigests) bool { return f.Missing }, func(f ImageFact, d ImageDigests, _ Version, driver string) string {
		// Lane FU9: the Podman driver does not pull at the gateway's start
		// (live check on rootless Podman 5.7.0), so the remedy is the
		// driver's own pull of the reference the gateway looks up.
		pull := "pull it by its pinned digest " + d.Index
		if validImageRef(f.Ref) {
			pull = "pull it with " + imagePullRemedy(driver, f.Ref) + " (the next probe checks it carries the pinned digest " + d.Index + ")"
		}
		return "the gateway's " + roleName(f.Role) + " " + quoteOr(f.Ref, "(no reference)") + " is not on this machine; the probe never pulls, and a gateway is not relied on to pull it at its start (the Podman driver does not), so " + pull
	}},
	{VerdictImageDigestMismatch, func(f ImageFact, d ImageDigests) bool { return !digestListed(f.RepoDigests, d.all()) }, func(f ImageFact, d ImageDigests, v Version, driver string) string {
		return "the gateway's " + roleName(f.Role) + " " + quoteOr(f.Ref, "(no reference)") + " is not the image OpenShell " + v.String() + " was tested with: none of its registry digests (" + digestList(f.RepoDigests) + ") is the pinned " + d.Index +
			"; a rebuilt, retagged or locally loaded image carries none. Pull the pinned image (a mirror must keep its digest), or set the gateway's " + driverConfigTable(driver) + " " + configKey(f.Role) + " to <repository>@" + d.Index
	}},
}

// roleName is a role's name in a reason.
func roleName(role string) string {
	if role == ImageSupervisor {
		return "supervisor image"
	}
	return "sandbox runtime image"
}

// configKey is the driver config key that names a role's image.
func configKey(role string) string {
	if role == ImageSupervisor {
		return "supervisor_image"
	}
	return "sandbox_runtime_image"
}

// digestListed reports whether one of the repo digests carries one of
// want (the digest after the last "@"; a mirror keeps the digest, not the
// repository).
func digestListed(repoDigests, want []string) bool {
	for _, rd := range repoDigests {
		i := strings.LastIndexByte(rd, '@')
		if i < 0 {
			continue
		}
		for _, w := range want {
			if rd[i+1:] == w {
				return true
			}
		}
	}
	return false
}

// digestList renders repo digests for a reason ("none recorded" for none),
// at most three, each a short token.
func digestList(ds []string) string {
	var out []string
	for _, d := range ds {
		if len(out) == 3 {
			out = append(out, "...")
			break
		}
		if validImageRef(d) {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		return "none recorded"
	}
	return strings.Join(out, ", ")
}

// ImageVerdict is probe row P8i over the tested row of version v and the
// facts read: "" when every role's image carries a pinned digest. A role
// with no fact is unread. driver is the gateway's compute driver (a
// missing image's remedy names its engine's pull; "" names every one).
func ImageVerdict(row TestedVersion, v Version, driver string, facts []ImageFact) (verdict, reason string) {
	for _, role := range ImageRoles {
		f := ImageFact{Role: role}
		for _, x := range facts {
			if x.Role == role {
				f = x
				break
			}
		}
		if f.NotUsed {
			continue
		}
		d := row.digestsFor(role)
		for _, r := range imageRules {
			if r.fails(f, d) {
				return r.verdict, r.reason(f, d, v, driver)
			}
		}
	}
	return ok, ""
}
