package tools

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	// ruleid: go.shell-interpolation
	_ = exec.Command("sh", "-c", "ping -c 1 "+host).Run()
	// ruleid: go.shell-interpolation
	_ = exec.Command("bash", "-c", fmt.Sprintf("dig %s", r.FormValue("name"))).Run()
	// ok: go.shell-interpolation
	_ = exec.Command("ping", "-c", "1", host).Run()
}

// The false-positive shapes of the 1.1.0 rule: the program's own paths and
// arguments.
func build(dir string) {
	out := filepath.Join(dir, "out")
	// ok: go.shell-interpolation
	_ = exec.Command("sh", "-c", "make -C "+dir+" OUT="+out).Run()
	// ok: go.shell-interpolation
	_ = exec.Command("sh", "-c", fmt.Sprintf("echo %s", os.Args[0])).Run()
}
