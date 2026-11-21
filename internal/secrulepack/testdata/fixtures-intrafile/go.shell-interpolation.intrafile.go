package tools

import (
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
)

// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that builds a shell line.
func ping(host string) error {
	// ruleid: go.shell-interpolation
	return exec.Command("sh", "-c", "ping -c 1 "+host).Run()
}

func handler(w http.ResponseWriter, r *http.Request) {
	_ = ping(r.URL.Query().Get("host"))
}

func requestedName(r *http.Request) string {
	return r.FormValue("name")
}

func lookup(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.shell-interpolation
	_ = exec.Command("bash", "-c", fmt.Sprintf("dig %s", requestedName(r))).Run()
}

// The sanitizer sits in the helper: the count is parsed to an integer
// before the caller builds the command line.
func asCount(value string) int {
	n, _ := strconv.Atoi(value)
	return n
}

func tail(w http.ResponseWriter, r *http.Request) {
	// ok: go.shell-interpolation
	_ = exec.Command("sh", "-c", fmt.Sprintf("tail -n %d app.log", asCount(r.FormValue("lines")))).Run()
}
