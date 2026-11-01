package hermesplugin

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPluginIsInstalledFile: the files WritePlugin wrote for a binary are
// installed files for that binary only; an edited file, another binary's
// render and a file the plugin does not ship are not.
func TestPluginIsInstalledFile(t *testing.T) {
	dir := t.TempDir()
	bin := `/opt/My "Tools"/observer`
	if err := WritePlugin(dir, bin); err != nil {
		t.Fatal(err)
	}
	read := func(rel string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, rel := range Files() {
		if !IsInstalledFile(rel, read(rel), []string{"/other/observer", bin}) {
			t.Errorf("%s as written is not an installed file", rel)
		}
	}
	initPy := read("__init__.py")
	if IsInstalledFile("__init__.py", initPy, []string{"/other/observer"}) {
		t.Error("__init__.py rendered for another binary counts")
	}
	if IsInstalledFile("__init__.py", append(append([]byte{}, initPy...), "\nimport os\n"...), []string{bin}) {
		t.Error("an edited __init__.py counts")
	}
	if IsInstalledFile("plugin.yaml", append(read("plugin.yaml"), ' '), []string{bin}) {
		t.Error("an edited plugin.yaml counts")
	}
	if IsInstalledFile("__pycache__/__init__.cpython-312.pyc", []byte("x"), []string{bin}) {
		t.Error("a file the plugin does not ship counts")
	}
	if err := WritePlugin(dir, ""); err != nil {
		t.Fatal(err)
	}
	if IsInstalledFile("__init__.py", read("__init__.py"), []string{""}) {
		t.Error("the bare PATH default counts as a binary")
	}
}
