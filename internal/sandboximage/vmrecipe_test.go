package sandboximage

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// vmrecipe_test.go pins deploy/sandbox-vm-image (lane SBX-P4): every input
// pinned by version and sha256 from one dated snapshot, no agent CLI or
// runtime in the rootfs list, no network wait in the initramfs, the
// verity root hash taken from the command line, nothing over 1 MB.

func readVMRecipe(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "sandbox-vm-image", name))
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > 1<<20 {
		t.Fatalf("%s is over 1 MB", name)
	}
	return string(b)
}

func TestVMRecipeIsPinned(t *testing.T) {
	env := readVMRecipe(t, "recipe.env")
	vals := map[string]string{}
	for _, line := range strings.Split(env, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && !strings.HasPrefix(k, "#") {
			vals[k] = strings.Trim(v, `"`)
		}
	}
	if !regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z$`).MatchString(vals["SNAPSHOT"]) {
		t.Fatalf("SNAPSHOT %q is not a dated snapshot", vals["SNAPSHOT"])
	}
	for _, k := range []string{"KERNEL", "MODULES", "BUSYBOX"} {
		if !hexRE.MatchString(vals[k+"_SHA256"]) || vals[k+"_VERSION"] == "" || !strings.HasPrefix(vals[k+"_FILE"], "pool/") {
			t.Errorf("%s is not pinned by version, pool file and sha256: %q %q %q", k, vals[k+"_VERSION"], vals[k+"_FILE"], vals[k+"_SHA256"])
		}
	}
	for _, p := range strings.Fields(vals["ROOTFS_PACKAGES"]) {
		name, ver, ok := strings.Cut(p, "=")
		if !ok || ver == "" {
			t.Errorf("rootfs package %q is not pinned by version", p)
		}
		if IsAgentPackage(name) || name == "nodejs" || name == "npm" {
			t.Errorf("rootfs package %q is an agent CLI or runtime (D-751 Q38)", name)
		}
	}
	if strings.Contains(strings.ToLower(env), "latest") {
		t.Error("the recipe names latest")
	}
}

func TestVMInitNeverWaitsForANetwork(t *testing.T) {
	init := readVMRecipe(t, "init")
	for _, bad := range []string{"network-online", "dhcp", "udhcpc", "ifup", "ip link"} {
		if strings.Contains(init, bad) {
			t.Errorf("the initramfs init mentions %q; the VM has no NIC", bad)
		}
	}
	for _, want := range []string{"observer.verity=", "veritysetup open", "-o ro", "sandbox-vm-init"} {
		if !strings.Contains(init, want) {
			t.Errorf("the initramfs init lacks %q", want)
		}
	}
	build := readVMRecipe(t, "build.sh")
	for _, want := range []string{"--mode=unshare", "sha256sum -c", "veritysetup format", "mkfs.ext4", "--reproducible"} {
		if !strings.Contains(build, want) {
			t.Errorf("build.sh lacks %q", want)
		}
	}
}

// vmSelfCheckTree writes a stand-in initramfs tree: a busybox that lists
// its applets, the recipe's real /init, veritysetup and its loader, and
// stand-in ELF modules whose modinfo names their dependencies.
func vmSelfCheckTree(t *testing.T, applets string, mods [][2]string) string {
	t.Helper()
	dir := t.TempDir()
	w := func(name string, b []byte, mode os.FileMode) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, mode); err != nil {
			t.Fatal(err)
		}
	}
	w("bin/busybox", []byte("#!/bin/sh\n[ \"$1\" = --list ] && printf '%s\\n' "+applets+"\n"), 0o755)
	w("init", []byte(readVMRecipe(t, "init")), 0o755)
	w("sbin/veritysetup", []byte("\x7fELF stand-in"), 0o755)
	w("lib64/ld-linux-x86-64.so.2", []byte("\x7fELF stand-in"), 0o755)
	var list []string
	for _, m := range mods {
		w("lib/modules/"+m[0]+".ko", []byte("\x7fELF\x02\x01\x00name="+m[0]+"\x00depends="+m[1]+"\x00vermagic=6.8.0\x00"), 0o644)
		list = append(list, m[0])
	}
	w("etc/observer-modules", []byte(strings.Join(list, "\n")+"\n"), 0o644)
	w("etc/observer-builtin", []byte("virtio_blk\n"), 0o644)
	return dir
}

// TestVMInitramfsSelfCheck (audit finding 4): the build-time check passes
// a complete tree and fails one missing an applet, one with a compressed
// module, one loading a module before its dependency, one without
// reed_solomon and an /init that calls a bare cat.
func TestVMInitramfsSelfCheck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the self-check is a bash script run on the Linux build host")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "deploy", "sandbox-vm-image", "selfcheck.sh"))
	if err != nil {
		t.Fatal(err)
	}
	env := readVMRecipe(t, "recipe.env")
	var required []string
	for _, line := range strings.Split(env, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "INITRAMFS_MODULES="); ok {
			required = strings.Fields(strings.Trim(v, `"`))
		}
	}
	if !strings.Contains(" "+strings.Join(required, " ")+" ", " reed_solomon ") {
		t.Fatalf("INITRAMFS_MODULES lacks reed_solomon: %v", required)
	}
	applets := "cat mkdir mount umount insmod poweroff switch_root"
	mods := [][2]string{
		{"dm-mod", ""},
		{"dm-bufio", "dm-mod"},
		{"reed_solomon", ""},
		{"dm-verity", "dm-bufio,reed_solomon"},
		{"fuse", ""},
		{"virtiofs", "fuse"},
		{"vsock", ""},
		{"vmw_vsock_virtio_transport_common", "vsock"},
		{"vmw_vsock_virtio_transport", "vmw_vsock_virtio_transport_common,vsock"},
	}
	run := func(dir string) (string, error) {
		out, err := exec.Command(bash, append([]string{script, dir}, required...)...).CombinedOutput()
		return string(out), err
	}
	if out, err := run(vmSelfCheckTree(t, applets, mods)); err != nil {
		t.Fatalf("a complete tree failed: %v\n%s", err, out)
	}
	for name, tc := range map[string]struct {
		dir  func() string
		want string
	}{
		"missing applet": {func() string { return vmSelfCheckTree(t, "cat mkdir mount umount insmod poweroff", mods) }, "no applet switch_root"},
		"compressed module": {func() string {
			d := vmSelfCheckTree(t, applets, mods)
			if err := os.WriteFile(filepath.Join(d, "lib/modules/fuse.ko"), []byte("\x28\xb5\x2f\xfd zstd"), 0o644); err != nil {
				t.Fatal(err)
			}
			return d
		}, "fuse.ko is not a plain ELF module"},
		"dependency order": {func() string {
			bad := append([][2]string{{"dm-verity", "dm-bufio,reed_solomon"}}, mods...)
			return vmSelfCheckTree(t, applets, bad)
		}, "dm-verity is loaded before its dependency dm-bufio"},
		"no reed_solomon": {func() string {
			var less [][2]string
			for _, m := range mods {
				if m[0] != "reed_solomon" {
					less = append(less, m)
				}
			}
			return vmSelfCheckTree(t, applets, less)
		}, "required module reed_solomon"},
		"bare cat": {func() string {
			d := vmSelfCheckTree(t, applets, mods)
			b, _ := os.ReadFile(filepath.Join(d, "init"))
			s := strings.Replace(string(b), "$($B cat /etc/observer-modules)", "$(cat /etc/observer-modules)", 1)
			if err := os.WriteFile(filepath.Join(d, "init"), []byte(s), 0o755); err != nil {
				t.Fatal(err)
			}
			return d
		}, "without $B"},
		"listed module missing": {func() string {
			d := vmSelfCheckTree(t, applets, mods)
			_ = os.Remove(filepath.Join(d, "lib/modules/virtiofs.ko"))
			return d
		}, "virtiofs is listed"},
	} {
		out, err := run(tc.dir())
		if err == nil || !strings.Contains(out, tc.want) {
			t.Errorf("%s: %v %q, want %q", name, err, out, tc.want)
		}
	}
}

// TestVMInitUsesBusyboxOnly: /init runs nothing outside busybox but
// veritysetup, and swallows no required module's error.
func TestVMInitUsesBusyboxOnly(t *testing.T) {
	init := readVMRecipe(t, "init")
	if strings.Contains(init, "$(cat ") || strings.Contains(init, "insmod \"/lib/modules/$m.ko.zst\"") {
		t.Fatal("/init calls a bare cat or loads a compressed module")
	}
	if strings.Contains(init, "insmod \"/lib/modules/$m.ko\" 2>/dev/null || ") && strings.Contains(init, "|| true\ndone") {
		t.Fatal("/init swallows a module load error")
	}
	if !strings.Contains(init, `fail "the module $m did not load"`) {
		t.Fatal("/init does not stop on a module that does not load")
	}
	build := readVMRecipe(t, "build.sh")
	for _, want := range []string{"selfcheck.sh", "depmod -b", "zstd -dq", "modules.builtin"} {
		if !strings.Contains(build, want) {
			t.Errorf("build.sh lacks %q", want)
		}
	}
}

// TestVMRecipeBuildsFromItsPockets (live run 2026-10-24, R1 to R3): the
// recipe's pinned versions are looked up in every pocket it names before
// anything is fetched, the security pocket among them (git
// 1:2.43.0-1ubuntu7.4 is only there), mmdebstrap gets exactly those pockets
// as sources, and the static busybox is found where the merged-/usr package
// ships it (usr/bin/busybox) and checked static rather than copied from a
// fixed bin/busybox.
func TestVMRecipeBuildsFromItsPockets(t *testing.T) {
	env := readVMRecipe(t, "recipe.env")
	build := readVMRecipe(t, "build.sh")
	var pockets string
	for _, line := range strings.Split(env, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "POCKETS="); ok {
			pockets = strings.Trim(v, `"`)
		}
	}
	for _, want := range []string{"${SUITE}", "${SUITE}-updates", "${SUITE}-security"} {
		if !strings.Contains(" "+pockets+" ", " "+want+" ") {
			t.Errorf("POCKETS %q lacks %s", pockets, want)
		}
	}
	for _, want := range []string{"recipecheck.sh\" pins", "recipecheck.sh\" installed", "recipecheck.sh\" busybox", "for pocket in $POCKETS"} {
		if !strings.Contains(build, want) {
			t.Errorf("build.sh lacks %q", want)
		}
	}
	if strings.Contains(build, `"$work/busybox/bin/busybox"`) || strings.Contains(build, "SUITE-updates $(echo") {
		t.Error("build.sh still copies a fixed bin/busybox or names its sources by hand")
	}
	if strings.Contains(env, "ca-certificates=20260816ubuntu0.24.04.1") {
		t.Error("the recipe pins a ca-certificates version its snapshot does not have")
	}
}

// TestVMRecipeCheckScript (R1 to R3): recipecheck.sh's three checks pass
// a good input and name each bad one: a pin in no pocket's index (with what
// each has), a rootfs holding another version, and a busybox that is
// missing, at the old path only as a link, or dynamically linked.
func TestVMRecipeCheckScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the recipe checks are bash run on the Linux build host")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "deploy", "sandbox-vm-image", "recipecheck.sh"))
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, error) {
		out, err := exec.Command(bash, append([]string{script}, args...)...).CombinedOutput()
		return string(out), err
	}
	idx := t.TempDir()
	w := func(p, s string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), mode); err != nil {
			t.Fatal(err)
		}
	}
	w(filepath.Join(idx, "noble_main"), "Package: git\nVersion: 1:2.43.0-1ubuntu7\n\nPackage: ca-certificates\nVersion: 20240203\n", 0o644)
	w(filepath.Join(idx, "noble-updates_main"), "Package: git\nVersion: 1:2.43.0-1ubuntu7.3\n\nPackage: ca-certificates\nVersion: 20260601~24.04.1\n", 0o644)
	if out, err := run("pins", idx, "git=1:2.43.0-1ubuntu7.3", "ca-certificates=20260601~24.04.1"); err != nil {
		t.Fatalf("good pins: %v %s", err, out)
	}
	out, err := run("pins", idx, "git=1:2.43.0-1ubuntu7.4", "ca-certificates=20260816ubuntu0.24.04.1")
	if err == nil || !strings.Contains(out, "git=1:2.43.0-1ubuntu7.4 is in none") || !strings.Contains(out, "noble-updates_main=1:2.43.0-1ubuntu7.3") || !strings.Contains(out, "ca-certificates=20260816ubuntu0.24.04.1 is in none") {
		t.Fatalf("bad pins: %v %s", err, out)
	}
	w(filepath.Join(idx, "noble-security_main"), "Package: git\nVersion: 1:2.43.0-1ubuntu7.4\n", 0o644)
	if out, err := run("pins", idx, "git=1:2.43.0-1ubuntu7.4"); err != nil {
		t.Fatalf("a pin only in the security pocket: %v %s", err, out)
	}

	tsv := filepath.Join(t.TempDir(), "packages.tsv")
	w(tsv, "git\t1:2.43.0-1ubuntu7.4\tamd64\nbash\t5.2.21-2ubuntu4\tamd64\n", 0o644)
	if out, err := run("installed", tsv, "git=1:2.43.0-1ubuntu7.4", "bash=5.2.21-2ubuntu4"); err != nil {
		t.Fatalf("installed: %v %s", err, out)
	}
	if out, err := run("installed", tsv, "git=1:2.43.0-1ubuntu7.3", "procps=2:4.0.4-4ubuntu3.3"); err == nil || !strings.Contains(out, "holds git 1:2.43.0-1ubuntu7.4") || !strings.Contains(out, "procps (not installed)") {
		t.Fatalf("installed drift: %v %s", err, out)
	}

	if _, err := exec.LookPath("readelf"); err != nil {
		t.Skip("no readelf for the busybox check")
	}
	// A static ELF header (no program headers, so no interpreter).
	static := "\x7fELF\x02\x01\x01" + strings.Repeat("\x00", 9) + "\x02\x00\x3e\x00\x01\x00\x00\x00" + strings.Repeat("\x00", 24) + "\x00\x00\x00\x00\x40\x00\x38\x00\x00\x00\x40\x00\x00\x00\x00\x00"
	deb := t.TempDir()
	w(filepath.Join(deb, "usr", "bin", "busybox"), static, 0o755)
	if out, err := run("busybox", deb); err != nil || strings.TrimSpace(out) != filepath.Join(deb, "usr", "bin", "busybox") {
		t.Fatalf("the merged-/usr busybox: %v %q", err, out)
	}
	empty := t.TempDir()
	if out, err := run("busybox", empty); err == nil || !strings.Contains(out, "no busybox") {
		t.Fatalf("no busybox: %v %s", err, out)
	}
	dyn := t.TempDir()
	if self, err := exec.LookPath("bash"); err == nil {
		b, _ := os.ReadFile(self)
		w(filepath.Join(dyn, "usr", "bin", "busybox"), string(b), 0o755)
		if out, err := run("busybox", dyn); err == nil || !strings.Contains(out, "program interpreter") {
			t.Fatalf("a dynamic busybox: %v %s", err, out)
		}
	}
}
