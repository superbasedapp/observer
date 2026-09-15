//go:build linux

package intervention

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

const bindingHeaderBytes = 512

// BuildInstallManifest inspects caller-resolved installed paths without
// executing them. It pins native executable identities, direct Node/Bun/Python
// script entrypoints, and only the native worker paths declared by the
// integration surface table. Device/inode binding proves which installed file
// is running; it does not prove vendor signature or package authenticity.
func BuildInstallManifest(ctx context.Context, candidates []InstalledCandidate) (InstallManifest, error) {
	if ctx == nil {
		return InstallManifest{}, fmt.Errorf("intervention.BuildInstallManifest: %w: nil context", ErrInvalidCandidate)
	}
	if err := ctx.Err(); err != nil {
		return InstallManifest{}, fmt.Errorf("intervention.BuildInstallManifest: %w", err)
	}

	surfaces := integration.AllInterventionSurfaces()
	manifest := InstallManifest{Surfaces: make([]SurfaceManifest, 0, len(surfaces))}
	index := make(map[string]int, len(surfaces))
	for _, spec := range surfaces {
		row := initialSurfaceManifest(spec)
		index[spec.ID] = len(manifest.Surfaces)
		manifest.Surfaces = append(manifest.Surfaces, row)
	}

	var candidateErrs []error
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return manifest, fmt.Errorf("intervention.BuildInstallManifest: %w", err)
		}
		surfaceID, err := resolveCandidateSurface(candidate)
		if err != nil {
			candidateErrs = append(candidateErrs, err)
			continue
		}
		idx, ok := index[surfaceID]
		if !ok {
			candidateErrs = append(candidateErrs, fmt.Errorf("%w: unknown surface", ErrInvalidCandidate))
			continue
		}
		row := &manifest.Surfaces[idx]
		if row.Spec.Class != integration.SurfaceDedicatedProcess {
			candidateErrs = append(candidateErrs, fmt.Errorf("%w: surface is not a dedicated process", ErrInvalidCandidate))
			continue
		}
		if row.State == BindingNotInstalled {
			row.Reasons = removeBindingReasons(row.Reasons, ReasonNoInstalledCandidate)
		}
		targets, reasons := bindInstalledCandidate(ctx, row.Spec, candidate)
		row.Targets = appendUniqueTargets(row.Targets, targets...)
		row.Reasons = appendUniqueBindingReasons(row.Reasons, reasons...)
		row.State = bindingState(len(row.Targets), len(row.Reasons))
	}

	for i := range manifest.Surfaces {
		row := &manifest.Surfaces[i]
		sort.Slice(row.Targets, func(i, j int) bool {
			if row.Targets[i].Executable.Path == row.Targets[j].Executable.Path {
				return row.Targets[i].Kind < row.Targets[j].Kind
			}
			return row.Targets[i].Executable.Path < row.Targets[j].Executable.Path
		})
	}
	return manifest, errors.Join(candidateErrs...)
}

func initialSurfaceManifest(spec integration.InterventionSurfaceSpec) SurfaceManifest {
	row := SurfaceManifest{Spec: spec}
	switch spec.Class {
	case integration.SurfaceSharedHost:
		row.State = BindingUnsupported
		row.Reasons = []BindingReason{ReasonSharedHost}
	case integration.SurfaceRemoteExecution:
		row.State = BindingUnsupported
		row.Reasons = []BindingReason{ReasonRemoteExecution}
	case integration.SurfaceUnclassified:
		row.State = BindingUnsupported
		row.Reasons = []BindingReason{ReasonUnclassifiedSurface}
	case integration.SurfaceDedicatedProcess:
		if spec.Binary == nil {
			row.State = BindingUnsupported
			row.Reasons = []BindingReason{ReasonNoBinaryCapability}
		} else {
			row.State = BindingNotInstalled
			row.Reasons = []BindingReason{ReasonNoInstalledCandidate}
		}
	default:
		row.State = BindingUnsupported
		row.Reasons = []BindingReason{ReasonUnclassifiedSurface}
	}
	return row
}

func resolveCandidateSurface(candidate InstalledCandidate) (string, error) {
	if strings.TrimSpace(candidate.Tool) == "" || strings.TrimSpace(candidate.Tool) != candidate.Tool ||
		strings.TrimSpace(candidate.LauncherPath) == "" {
		return "", fmt.Errorf("%w: tool and launcher path are required", ErrInvalidCandidate)
	}
	surfaces, ok := integration.InterventionFor(candidate.Tool)
	if !ok {
		return "", fmt.Errorf("%w: unknown tool", ErrInvalidCandidate)
	}
	if candidate.SurfaceID != "" {
		for _, surface := range surfaces {
			if surface.ID == candidate.SurfaceID {
				return candidate.SurfaceID, nil
			}
		}
		return "", fmt.Errorf("%w: %s", ErrInvalidCandidate, ReasonCandidateSurfaceUnknown)
	}
	var dedicated []string
	for _, surface := range surfaces {
		if surface.Class == integration.SurfaceDedicatedProcess {
			dedicated = append(dedicated, surface.ID)
		}
	}
	if len(dedicated) != 1 {
		return "", fmt.Errorf("%w: surface ID required", ErrInvalidCandidate)
	}
	return dedicated[0], nil
}

func bindInstalledCandidate(ctx context.Context, spec integration.InterventionSurfaceSpec, candidate InstalledCandidate) ([]InstallTarget, []BindingReason) {
	if spec.Binary == nil || !declaredUnixLauncherName(spec.Binary.Names.Unix, filepath.Base(filepath.Clean(candidate.LauncherPath))) {
		return nil, []BindingReason{ReasonCandidatePathInvalid}
	}
	launcher, mode, head, err := inspectInstalledFile(ctx, candidate.LauncherPath)
	if err != nil {
		return nil, []BindingReason{installedFileReason(err)}
	}
	if mode == installedELF {
		if !spec.Binding.AllowNative {
			return nil, []BindingReason{ReasonNativeNotDeclared}
		}
		if !spec.Binding.Invocation.AllowsCLI() {
			return nil, []BindingReason{ReasonInvocationUnknown}
		}
		if !declaredUnixLauncherName(spec.Binary.Names.Unix, filepath.Base(launcher.Path)) {
			return nil, []BindingReason{ReasonGenericProcessHost}
		}
		if forbiddenNativeTarget(ctx, launcher, candidate.Interpreters) {
			return nil, []BindingReason{ReasonGenericProcessHost}
		}
		return []InstallTarget{{Kind: TargetNativeExecutable, Executable: launcher}}, nil
	}

	var targets []InstallTarget
	var reasons []BindingReason
	if mode == installedScript {
		kind, shebangPath, direct, shell := parseSupportedShebang(head)
		switch {
		case shell:
			reasons = append(reasons, ReasonShellLauncher)
		case !direct:
			reasons = append(reasons, ReasonLauncherFormUnknown)
		case !declaresInterpreter(spec.Binding.Interpreters, kind):
			reasons = append(reasons, ReasonInterpreterNotDeclared)
		case !spec.Binding.Invocation.AllowsCLI():
			reasons = append(reasons, ReasonInvocationUnknown)
		default:
			interpreterPaths := []string{shebangPath}
			invalidInterpreter := false
			if shebangPath == "" {
				interpreterPaths, invalidInterpreter = suppliedInterpreterPaths(candidate.Interpreters, kind)
			}
			if invalidInterpreter || len(interpreterPaths) == 0 {
				reasons = append(reasons, ReasonInterpreterUnresolved)
			}
			for _, interpreterPath := range interpreterPaths {
				interpreter, interpreterMode, _, ierr := inspectInstalledFile(ctx, interpreterPath)
				if ierr != nil || interpreterMode != installedELF {
					reasons = append(reasons, ReasonInterpreterUnresolved)
					continue
				}
				entrypoint := launcher
				targets = append(targets, InstallTarget{
					Kind:       TargetInterpretedEntrypoint,
					Executable: interpreter,
					Entrypoint: &entrypoint,
				})
			}
		}
	} else {
		reasons = append(reasons, ReasonLauncherFormUnknown)
	}

	if len(spec.Binding.Workers) > 0 && !spec.Binding.Invocation.AllowsCLI() {
		reasons = append(reasons, ReasonInvocationUnknown)
	} else {
		workerTargets, workerSeen, workerInvalid, genericWorker := discoverDeclaredWorkers(ctx, launcher.Path, spec.Binding.Workers, candidate.Interpreters)
		targets = append(targets, workerTargets...)
		if len(spec.Binding.Workers) > 0 && !workerSeen {
			reasons = append(reasons, ReasonWorkerNotFound)
		}
		if workerInvalid {
			reasons = append(reasons, ReasonWorkerInvalid)
		}
		if genericWorker {
			reasons = append(reasons, ReasonGenericProcessHost)
		}
	}
	if len(targets) > 0 {
		// The unsupported launcher is expected for a declared native-worker
		// layout. Its shell/JS process is not a target and does not make the
		// exact worker bindings partial.
		reasons = removeBindingReasons(reasons, ReasonShellLauncher, ReasonInterpreterNotDeclared, ReasonLauncherFormUnknown)
	}
	return appendUniqueTargets(nil, targets...), appendUniqueBindingReasons(nil, reasons...)
}

func declaredUnixLauncherName(names []string, candidate string) bool {
	for _, name := range names {
		if name == candidate {
			return true
		}
	}
	return false
}

type installedMode uint8

const (
	installedUnknown installedMode = iota
	installedELF
	installedScript
)

func inspectInstalledFile(ctx context.Context, path string) (InstalledFile, installedMode, []byte, error) {
	if err := ctx.Err(); err != nil {
		return InstalledFile{}, installedUnknown, nil, err
	}
	if path == "" || !filepath.IsAbs(path) {
		return InstalledFile{}, installedUnknown, nil, ErrInvalidCandidate
	}
	real, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return InstalledFile{}, installedUnknown, nil, err
	}
	real, err = filepath.Abs(real)
	if err != nil {
		return InstalledFile{}, installedUnknown, nil, err
	}
	before, err := os.Lstat(real)
	if err != nil {
		return InstalledFile{}, installedUnknown, nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0o111 == 0 {
		return InstalledFile{}, installedUnknown, nil, errInstalledNotExecutable
	}
	fd, err := unix.Open(real, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return InstalledFile{}, installedUnknown, nil, err
	}
	f := os.NewFile(uintptr(fd), real)
	if f == nil {
		_ = unix.Close(fd)
		return InstalledFile{}, installedUnknown, nil, ErrInvalidCandidate
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return InstalledFile{}, installedUnknown, nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return InstalledFile{}, installedUnknown, nil, errInstalledNotExecutable
	}
	identity, ok := fileIdentity(info)
	if !ok {
		return InstalledFile{}, installedUnknown, nil, ErrInvalidCandidate
	}
	head, err := readHead(ctx, f, bindingHeaderBytes)
	if err != nil {
		return InstalledFile{}, installedUnknown, nil, err
	}
	mode := installedUnknown
	switch {
	case len(head) >= 4 && bytes.Equal(head[:4], []byte{0x7f, 'E', 'L', 'F'}):
		mode = installedELF
	case bytes.HasPrefix(head, []byte("#!")):
		mode = installedScript
	}
	return InstalledFile{Path: real, Identity: identity}, mode, head, nil
}

var errInstalledNotExecutable = errors.New("installed file is not a regular executable")

func fileIdentity(info os.FileInfo) (ExecutableIdentity, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Dev == 0 || stat.Ino == 0 {
		return ExecutableIdentity{}, false
	}
	//nolint:unconvert // dev_t has a narrower type on some Linux architectures.
	return ExecutableIdentity{Device: uint64(stat.Dev), Inode: stat.Ino}, true
}

func readHead(ctx context.Context, r io.Reader, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(r, limit))
}

func installedFileReason(err error) BindingReason {
	if errors.Is(err, errInstalledNotExecutable) {
		return ReasonCandidateNotExecutable
	}
	return ReasonCandidatePathInvalid
}

func parseSupportedShebang(head []byte) (integration.InterpreterKind, string, bool, bool) {
	line := string(head)
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "#!")))
	if len(fields) == 0 {
		return "", "", false, false
	}
	interpreter := fields[0]
	if filepath.Base(interpreter) == "env" {
		if len(fields) != 2 || strings.HasPrefix(fields[1], "-") || strings.Contains(fields[1], "=") {
			return "", "", false, false
		}
		kind, shell := interpreterKind(filepath.Base(fields[1]))
		return kind, "", kind != "" && !shell, shell
	}
	if len(fields) != 1 || !filepath.IsAbs(interpreter) {
		return "", "", false, false
	}
	kind, shell := interpreterKind(filepath.Base(interpreter))
	return kind, interpreter, kind != "" && !shell, shell
}

func interpreterKind(name string) (integration.InterpreterKind, bool) {
	switch {
	case name == "node" || name == "nodejs":
		return integration.InterpreterNode, false
	case name == "bun":
		return integration.InterpreterBun, false
	case name == "python" || strings.HasPrefix(name, "python3"):
		return integration.InterpreterPython, false
	case name == "sh" || name == "bash" || name == "dash" || name == "zsh":
		return "", true
	default:
		return "", false
	}
}

func declaresInterpreter(declared []integration.InterpreterKind, kind integration.InterpreterKind) bool {
	for _, candidate := range declared {
		if candidate == kind {
			return true
		}
	}
	return false
}

func suppliedInterpreterPaths(interpreters []InstalledInterpreter, kind integration.InterpreterKind) ([]string, bool) {
	var paths []string
	seen := make(map[string]bool)
	invalid := false
	for _, interpreter := range interpreters {
		if interpreter.Kind != kind {
			continue
		}
		if !filepath.IsAbs(interpreter.Path) {
			invalid = true
			continue
		}
		path := filepath.Clean(interpreter.Path)
		if !seen[path] {
			seen[path] = true
			paths = append(paths, path)
		}
	}
	return paths, invalid
}

func discoverDeclaredWorkers(ctx context.Context, launcherPath string, specs []integration.WorkerDiscoverySpec, interpreters []InstalledInterpreter) ([]InstallTarget, bool, bool, bool) {
	var targets []InstallTarget
	seen := false
	invalid := false
	generic := false
	launcherDir := filepath.Dir(launcherPath)
	for _, spec := range specs {
		if err := ctx.Err(); err != nil {
			return targets, seen, true, generic
		}
		var paths []string
		switch spec.Kind {
		case integration.WorkerExactRelative:
			if spec.Relative == "" || filepath.IsAbs(spec.Relative) {
				invalid = true
				continue
			}
			paths = []string{filepath.Join(launcherDir, filepath.FromSlash(spec.Relative))}
		case integration.WorkerVersionedSibling:
			if spec.Prefix == "" || filepath.Base(spec.Prefix) != spec.Prefix {
				invalid = true
				continue
			}
			entries, err := os.ReadDir(launcherDir)
			if err != nil {
				invalid = true
				continue
			}
			for _, entry := range entries {
				if !strings.HasPrefix(entry.Name(), spec.Prefix) || !validVersionSuffix(strings.TrimPrefix(entry.Name(), spec.Prefix)) {
					continue
				}
				if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
					generic = true
					continue
				}
				paths = append(paths, filepath.Join(launcherDir, entry.Name()))
			}
		default:
			invalid = true
			continue
		}
		for _, path := range paths {
			worker, mode, _, err := inspectInstalledFile(ctx, path)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil || mode != installedELF {
				invalid = true
				continue
			}
			switch spec.Kind {
			case integration.WorkerExactRelative:
				if worker.Path != filepath.Clean(path) {
					generic = true
					continue
				}
			case integration.WorkerVersionedSibling:
				if filepath.Dir(worker.Path) != launcherDir || !strings.HasPrefix(filepath.Base(worker.Path), spec.Prefix) {
					generic = true
					continue
				}
			}
			if forbiddenNativeTarget(ctx, worker, interpreters) {
				generic = true
				continue
			}
			seen = true
			targets = append(targets, InstallTarget{Kind: TargetNativeExecutable, Executable: worker})
		}
	}
	return appendUniqueTargets(nil, targets...), seen, invalid, generic
}

func validVersionSuffix(s string) bool {
	if s == "" || s[0] < '0' || s[0] > '9' || strings.Contains(s, "..") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == '+' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func forbiddenNativeTarget(ctx context.Context, file InstalledFile, interpreters []InstalledInterpreter) bool {
	for _, interpreter := range interpreters {
		candidate, _, _, err := inspectInstalledFile(ctx, interpreter.Path)
		if err == nil && candidate.Identity == file.Identity {
			return true
		}
	}
	for _, path := range genericExecutablePaths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		identity, ok := fileIdentity(info)
		if ok && identity == file.Identity {
			return true
		}
	}
	if genericExecutableNames[strings.ToLower(filepath.Base(file.Path))] {
		return true
	}
	// The matcher excludes the controller and its ancestor PIDs separately.
	// Requiring executable access to every ancestor makes a legitimate user
	// controller lose all targets when its parent chain includes a privileged
	// service manager or sudo process. Only the controller's own executable is
	// an unconditional installation exclusion here.
	info, err := os.Stat("/proc/self/exe")
	if err != nil {
		return true
	}
	identity, ok := fileIdentity(info)
	return !ok || identity == file.Identity
}

var genericExecutablePaths = []string{
	"/bin/bash", "/bin/dash", "/bin/sh", "/bin/zsh",
	"/usr/bin/bash", "/usr/bin/bun", "/usr/bin/dash", "/usr/bin/env",
	"/usr/bin/node", "/usr/bin/nodejs", "/usr/bin/python", "/usr/bin/python3",
	"/usr/bin/sh", "/usr/bin/zsh",
}

var genericExecutableNames = map[string]bool{
	"bash": true, "bun": true, "chrome": true, "chromium": true,
	"code": true, "dash": true, "electron": true, "env": true,
	"firefox": true, "idea": true, "node": true, "nodejs": true,
	"pycharm": true, "python": true, "python3": true, "sh": true,
	"webstorm": true, "zed": true, "zsh": true,
}

func bindingState(targets, reasons int) BindingState {
	switch {
	case targets > 0 && reasons == 0:
		return BindingReady
	case targets > 0:
		return BindingPartial
	default:
		return BindingUnsupported
	}
}

func appendUniqueTargets(dst []InstallTarget, values ...InstallTarget) []InstallTarget {
	for _, value := range values {
		duplicate := false
		for _, existing := range dst {
			if existing.Kind == value.Kind && existing.Executable.Identity == value.Executable.Identity &&
				sameEntrypoint(existing.Entrypoint, value.Entrypoint) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			dst = append(dst, value)
		}
	}
	return dst
}

func sameEntrypoint(a, b *InstalledFile) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Path == b.Path && a.Identity == b.Identity
}

func appendUniqueBindingReasons(dst []BindingReason, values ...BindingReason) []BindingReason {
	for _, value := range values {
		if value == "" {
			continue
		}
		found := false
		for _, existing := range dst {
			if existing == value {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, value)
		}
	}
	sort.Slice(dst, func(i, j int) bool { return dst[i] < dst[j] })
	return dst
}

func removeBindingReasons(in []BindingReason, values ...BindingReason) []BindingReason {
	remove := make(map[BindingReason]bool, len(values))
	for _, value := range values {
		remove[value] = true
	}
	out := in[:0]
	for _, value := range in {
		if !remove[value] {
			out = append(out, value)
		}
	}
	return out
}

// ReadProcessEvidence reads stable process identity and the minimum argv
// evidence required by an exact manifest target. Native and interpreted argv
// are reduced to closed surface/target classes immediately; raw values are
// never returned. Interpreted targets retain only their exact direct script
// entrypoint. The process identity is re-read after all required observations.
func ReadProcessEvidence(ctx context.Context, manifest InstallManifest, pid int) (ProcessEvidence, error) {
	id, err := Inspect(ctx, pid)
	if err != nil {
		return ProcessEvidence{}, fmt.Errorf("intervention.ReadProcessEvidence: %w", err)
	}
	evidence := ProcessEvidence{Identity: id}
	hasNative := manifestHasNative(manifest, id)
	hasInterpreter := manifestHasInterpreter(manifest, id.Executable)
	if !hasNative && !hasInterpreter {
		return evidence, nil
	}
	arguments, err := readInvocationArguments(ctx, fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ProcessEvidence{}, fmt.Errorf("intervention.ReadProcessEvidence: invocation: %w", err)
	}
	if hasNative {
		for _, surface := range manifest.Surfaces {
			if !surfaceHasNativeIdentity(surface, id) {
				continue
			}
			evidence.Invocations = append(evidence.Invocations, InvocationEvidence{
				SurfaceID: surface.Spec.ID,
				Target:    TargetNativeExecutable,
				Class:     ClassifyInvocation(surface.Spec.Binding.Invocation, arguments[0].value, arguments[0].present),
			})
		}
	}
	if hasInterpreter {
		entrypoint, err := readDirectEntrypoint(ctx, manifest, pid, arguments[0])
		if err != nil {
			return ProcessEvidence{}, fmt.Errorf("intervention.ReadProcessEvidence: entrypoint: %w", err)
		}
		evidence.Entrypoint = entrypoint
		if entrypoint != nil {
			for _, surface := range manifest.Surfaces {
				if !surfaceHasInterpretedIdentity(surface, id, *entrypoint) {
					continue
				}
				evidence.Invocations = append(evidence.Invocations, InvocationEvidence{
					SurfaceID: surface.Spec.ID,
					Target:    TargetInterpretedEntrypoint,
					Class:     ClassifyInvocation(surface.Spec.Binding.Invocation, arguments[1].value, arguments[1].present),
				})
			}
		}
	}
	after, err := Inspect(ctx, pid)
	if err != nil {
		return ProcessEvidence{}, fmt.Errorf("intervention.ReadProcessEvidence: revalidate: %w", err)
	}
	if !sameIdentity(id, after) {
		return ProcessEvidence{}, ErrIdentityMismatch
	}
	return evidence, nil
}

func manifestHasNative(manifest InstallManifest, identity Identity) bool {
	for _, surface := range manifest.Surfaces {
		if surfaceHasNativeIdentity(surface, identity) {
			return true
		}
	}
	return false
}

func surfaceHasNativeIdentity(surface SurfaceManifest, identity Identity) bool {
	if surface.Spec.Class != integration.SurfaceDedicatedProcess ||
		(surface.State != BindingReady && surface.State != BindingPartial) {
		return false
	}
	for _, target := range surface.Targets {
		if target.Kind == TargetNativeExecutable && nativeExecutableMatches(target, identity) {
			return true
		}
	}
	return false
}

func manifestHasInterpreter(manifest InstallManifest, executable ExecutableIdentity) bool {
	for _, surface := range manifest.Surfaces {
		for _, target := range surface.Targets {
			if target.Kind == TargetInterpretedEntrypoint && target.Executable.Identity == executable {
				return true
			}
		}
	}
	return false
}

func surfaceHasInterpretedIdentity(surface SurfaceManifest, identity Identity, entrypoint EntrypointEvidence) bool {
	if surface.Spec.Class != integration.SurfaceDedicatedProcess ||
		(surface.State != BindingReady && surface.State != BindingPartial) {
		return false
	}
	for _, target := range surface.Targets {
		if target.Kind == TargetInterpretedEntrypoint && nativeExecutableMatches(target, identity) &&
			target.Entrypoint != nil && target.Entrypoint.Path == entrypoint.Path &&
			target.Entrypoint.Identity == entrypoint.Identity {
			return true
		}
	}
	return false
}

func readDirectEntrypoint(ctx context.Context, manifest InstallManifest, pid int, argument transientArgument) (*EntrypointEvidence, error) {
	if !argument.present || argument.value == "" {
		return nil, ErrInspectionUnavailable
	}
	path := argument.value
	if !filepath.IsAbs(path) {
		cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
		if err != nil {
			return nil, err
		}
		path = filepath.Join(cwd, path)
	}
	file, _, _, err := inspectInstalledFile(ctx, path)
	if err != nil {
		if lexicalManifestEntrypoint(manifest, path) {
			return nil, err
		}
		return nil, nil
	}
	if !manifestEntrypoint(manifest, file) {
		return nil, nil
	}
	return &EntrypointEvidence{Path: file.Path, Identity: file.Identity}, nil
}

func lexicalManifestEntrypoint(manifest InstallManifest, path string) bool {
	clean := filepath.Clean(path)
	for _, surface := range manifest.Surfaces {
		for _, target := range surface.Targets {
			if target.Entrypoint != nil && target.Entrypoint.Path == clean {
				return true
			}
		}
	}
	return false
}

func manifestEntrypoint(manifest InstallManifest, file InstalledFile) bool {
	for _, surface := range manifest.Surfaces {
		for _, target := range surface.Targets {
			if target.Entrypoint != nil && target.Entrypoint.Path == file.Path && target.Entrypoint.Identity == file.Identity {
				return true
			}
		}
	}
	return false
}

type transientArgument struct {
	value   string
	present bool
}

const invocationFieldBytes = 32 * 1024

func readInvocationArguments(ctx context.Context, path string) ([2]transientArgument, error) {
	var arguments [2]transientArgument
	if ctx == nil {
		return arguments, ErrInspectionUnavailable
	}
	if err := ctx.Err(); err != nil {
		return arguments, err
	}
	f, err := os.Open(path)
	if err != nil {
		return arguments, err
	}
	defer f.Close()
	reader := bufio.NewReader(io.LimitReader(f, 3*invocationFieldBytes))
	for field := 0; field < 3; field++ {
		value, present, err := readCmdlineField(ctx, reader)
		if err != nil {
			return arguments, err
		}
		if !present {
			if field == 0 {
				return arguments, ErrInspectionUnavailable
			}
			return arguments, nil
		}
		if field > 0 {
			arguments[field-1] = transientArgument{value: value, present: true}
		}
	}
	return arguments, nil
}

func readCmdlineField(ctx context.Context, reader *bufio.Reader) (string, bool, error) {
	var value []byte
	for {
		if err := ctx.Err(); err != nil {
			return "", false, err
		}
		part, readErr := reader.ReadBytes(0)
		value = append(value, part...)
		if len(value) > invocationFieldBytes {
			return "", false, ErrInspectionUnavailable
		}
		if errors.Is(readErr, io.EOF) {
			if len(value) == 0 {
				return "", false, nil
			}
			return "", false, ErrInspectionUnavailable
		}
		if readErr != nil {
			return "", false, readErr
		}
		if len(part) > 0 && part[len(part)-1] == 0 {
			return string(value[:len(value)-1]), true, nil
		}
	}
}

// AncestorPIDs returns pid followed by its parent chain. Cycles, malformed
// parent data, and a chain longer than the kernel PID namespace can reasonably
// supply are rejected instead of producing a partial exclusion set.
func AncestorPIDs(ctx context.Context, pid int) ([]int, error) {
	if ctx == nil || pid <= 1 {
		return nil, fmt.Errorf("intervention.AncestorPIDs: %w", ErrInvalidIdentity)
	}
	seen := make(map[int]bool)
	var out []int
	for current := pid; current > 1; {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("intervention.AncestorPIDs: %w", err)
		}
		if seen[current] || len(out) > 4096 {
			return nil, fmt.Errorf("intervention.AncestorPIDs: malformed parent chain: %w", ErrInspectionUnavailable)
		}
		seen[current] = true
		out = append(out, current)
		parent, _, err := readStatusIdentity(current)
		if err != nil {
			return nil, fmt.Errorf("intervention.AncestorPIDs: %w", err)
		}
		current = parent
	}
	return out, nil
}

func readStatusIdentity(pid int) (ppid, uid int, err error) {
	ppid, uid, _, err = readStatusIdentityState(pid)
	return ppid, uid, err
}

func readStatusIdentityState(pid int) (ppid, uid int, state byte, err error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0, 0, err
	}
	ppid = -1
	uid = -1
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "PPid:":
			ppid, err = strconv.Atoi(fields[1])
			if err != nil {
				return 0, 0, 0, err
			}
		case "Uid:":
			uid, err = strconv.Atoi(fields[1])
			if err != nil {
				return 0, 0, 0, err
			}
		case "State:":
			if len(fields[1]) == 1 {
				state = fields[1][0]
			}
		}
	}
	if ppid < 0 || uid < 0 || state == 0 {
		return 0, 0, 0, ErrInspectionUnavailable
	}
	return ppid, uid, state, nil
}

func processStateExited(state byte) bool {
	return state == 'Z' || state == 'X' || state == 'x'
}

// ScanInstalledProcesses reconciles existing Linux processes for target UID.
// It returns only exact, unambiguous targets. A process disappearing during
// the scan increments TransientGone; inspection failures for a known target
// UID make Complete false.
func ScanInstalledProcesses(ctx context.Context, manifest InstallManifest, opts ScanOptions) (ScanResult, error) {
	if ctx == nil || opts.TargetUID < 0 {
		return ScanResult{}, fmt.Errorf("intervention.ScanInstalledProcesses: %w", ErrInvalidIdentity)
	}
	controllerPID := opts.ControllerPID
	if controllerPID == 0 {
		controllerPID = os.Getpid()
	}
	forbidden, err := AncestorPIDs(ctx, controllerPID)
	if err != nil {
		return ScanResult{}, fmt.Errorf("intervention.ScanInstalledProcesses: ancestors: %w", err)
	}
	controllerNS := ""
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return ScanResult{}, fmt.Errorf("intervention.ScanInstalledProcesses: enumerate: %w", err)
	}
	result := ScanResult{Complete: true}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return result, fmt.Errorf("intervention.ScanInstalledProcesses: %w", err)
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		_, uid, state, err := readStatusIdentityState(pid)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				result.TransientGone++
				continue
			}
			result.Complete = false
			result.Failures = append(result.Failures, ProcessScanFailure{PID: pid, Reason: ScanFailureInspectionUnavailable})
			continue
		}
		if uid != opts.TargetUID {
			continue
		}
		// Zombies and dead tasks have already exited and cannot accrue usage or
		// receive a useful intervention signal. Their missing /proc/PID/exe is
		// expected, so do not turn that into incomplete scan evidence.
		if processStateExited(state) {
			continue
		}
		identity, err := inspectScanProcess(ctx, pid, opts)
		if err != nil {
			if processDisappeared(err) {
				result.TransientGone++
				continue
			}
			result.Complete = false
			reason := ScanFailureInspectionUnavailable
			if strings.Contains(err.Error(), "entrypoint") {
				reason = ScanFailureEntrypointUnavailable
			}
			result.Failures = append(result.Failures, ProcessScanFailure{PID: pid, Reason: reason})
			continue
		}
		if !manifestHasExecutable(manifest, identity.Executable) {
			continue
		}
		if manifestHasInterpreter(manifest, identity.Executable) {
			if controllerNS == "" {
				controllerNS, err = os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", controllerPID))
				if err != nil {
					return result, fmt.Errorf("intervention.ScanInstalledProcesses: controller namespace: %w", err)
				}
			}
			mountNS, nsErr := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", pid))
			if nsErr != nil {
				if errors.Is(nsErr, os.ErrNotExist) {
					result.TransientGone++
					continue
				}
				result.Complete = false
				result.Failures = append(result.Failures, ProcessScanFailure{PID: pid, Reason: ScanFailureInspectionUnavailable})
				continue
			}
			if mountNS != controllerNS {
				result.Complete = false
				result.Failures = append(result.Failures, ProcessScanFailure{PID: pid, Reason: ScanFailureMountNamespace})
				continue
			}
		}
		evidence, err := ReadProcessEvidence(ctx, manifest, pid)
		if err != nil {
			if processDisappeared(err) {
				result.TransientGone++
				continue
			}
			result.Complete = false
			reason := ScanFailureInspectionUnavailable
			if strings.Contains(err.Error(), "entrypoint") {
				reason = ScanFailureEntrypointUnavailable
			}
			result.Failures = append(result.Failures, ProcessScanFailure{PID: pid, Reason: reason})
			continue
		}
		match := MatchInstalledProcess(manifest, evidence, MatchOptions{TargetUID: opts.TargetUID, ForbiddenPIDs: forbidden})
		recordScanMatch(&result, evidence, match)
	}
	sort.Slice(result.Matches, func(i, j int) bool {
		if result.Matches[i].SurfaceID == result.Matches[j].SurfaceID {
			return result.Matches[i].Identity.PID < result.Matches[j].Identity.PID
		}
		return result.Matches[i].SurfaceID < result.Matches[j].SurfaceID
	})
	return result, nil
}

func manifestHasExecutable(manifest InstallManifest, executable ExecutableIdentity) bool {
	for _, surface := range manifest.Surfaces {
		for _, target := range surface.Targets {
			if target.Executable.Identity == executable {
				return true
			}
		}
	}
	return false
}

// RevalidateBinding re-reads stable process identity and exact interpreted
// entrypoint evidence immediately before control. It also recomputes the
// controller/ancestor exclusion set and refuses a different or ambiguous
// surface.
func RevalidateBinding(ctx context.Context, manifest InstallManifest, expected Identity, surfaceID string, opts ScanOptions) (ProcessMatch, error) {
	if ctx == nil || !validIdentity(expected) || strings.TrimSpace(surfaceID) == "" || opts.TargetUID < 0 {
		return ProcessMatch{}, fmt.Errorf("intervention.RevalidateBinding: %w", ErrInvalidIdentity)
	}
	controllerPID := opts.ControllerPID
	if controllerPID == 0 {
		controllerPID = os.Getpid()
	}
	forbidden, err := AncestorPIDs(ctx, controllerPID)
	if err != nil {
		return ProcessMatch{}, fmt.Errorf("intervention.RevalidateBinding: ancestors: %w", err)
	}
	if manifestHasInterpreter(manifest, expected.Executable) {
		controllerNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", controllerPID))
		if err != nil {
			return ProcessMatch{}, fmt.Errorf("intervention.RevalidateBinding: controller namespace: %w", err)
		}
		targetNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", expected.PID))
		if err != nil {
			return ProcessMatch{}, fmt.Errorf("intervention.RevalidateBinding: target namespace: %w", err)
		}
		if targetNS != controllerNS {
			return ProcessMatch{}, fmt.Errorf("intervention.RevalidateBinding: %w: mount namespace", ErrBindingMismatch)
		}
	}
	evidence, err := ReadProcessEvidence(ctx, manifest, expected.PID)
	if err != nil {
		return ProcessMatch{}, fmt.Errorf("intervention.RevalidateBinding: evidence: %w", err)
	}
	if !sameIdentity(evidence.Identity, expected) {
		return ProcessMatch{}, fmt.Errorf("intervention.RevalidateBinding: %w", ErrIdentityMismatch)
	}
	result := MatchInstalledProcess(manifest, evidence, MatchOptions{TargetUID: opts.TargetUID, ForbiddenPIDs: forbidden})
	if result.State == MatchAmbiguous {
		return ProcessMatch{}, fmt.Errorf("intervention.RevalidateBinding: %w", ErrBindingAmbiguous)
	}
	if result.State != MatchBound || len(result.Matches) != 1 || result.Matches[0].SurfaceID != surfaceID {
		return ProcessMatch{}, fmt.Errorf("intervention.RevalidateBinding: %w", ErrBindingMismatch)
	}
	return result.Matches[0], nil
}

func processDisappeared(err error) bool {
	return errors.Is(err, ErrProcessGone) || errors.Is(err, os.ErrNotExist)
}
