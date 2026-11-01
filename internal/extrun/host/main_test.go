package host

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"testing"
	"time"
)

// helperEnv marks a run of this test binary as the helper program the
// real-process tests start through the runner.
const helperEnv = "EXTRUN_HELPER=1"

// helperPidFile is the file, in its working directory, where the helper
// writes its grandchild's pid once the grandchild has started.
const helperPidFile = "grandchild.pid"

// TestMain turns the test binary into the helper program when helperEnv is
// set, so the tests need no external binary.
func TestMain(m *testing.M) {
	dieAfterStarted()
	// The test binary offers the trampoline exactly as the observer binary
	// does: first thing in main.
	if code, ok := TrampolineDispatch(os.Args); ok {
		os.Exit(code)
	}
	if os.Getenv("EXTRUN_HELPER") == "1" {
		os.Exit(helper(os.Args[1:]))
	}
	os.Exit(m.Run())
}

// helper runs one behaviour named by args[0].
func helper(args []string) int {
	if len(args) == 0 {
		return 100
	}
	self, err := os.Executable()
	if err != nil {
		return 101
	}
	switch args[0] {
	case "env":
		env := os.Environ()
		sort.Strings(env)
		for _, kv := range env {
			fmt.Println(kv)
		}
	case "exit":
		n, _ := strconv.Atoi(args[1])
		return n
	case "cat":
		_, _ = io.Copy(os.Stdout, os.Stdin)
	case "sleep":
		time.Sleep(time.Hour)
	case "flood":
		chunk := make([]byte, 64<<10)
		for {
			if _, err := os.Stdout.Write(chunk); err != nil {
				return 0
			}
		}
	case "floodkid":
		// A sleeping grandchild in its own session (outside the group),
		// then a flood: the output cap must end both.
		c := exec.Command(self, "sleep")
		c.Env = []string{helperEnv}
		c.SysProcAttr = newSessionAttr()
		if err := c.Start(); err != nil {
			return 102
		}
		fmt.Println(c.Process.Pid)
		chunk := make([]byte, 64<<10)
		for {
			if _, err := os.Stdout.Write(chunk); err != nil {
				return 0
			}
		}
	case "grandchild", "background", "escape":
		// Start a sleeping grandchild that holds our stdout, print its pid,
		// then sleep (grandchild), exit at once (background), or exit at
		// once with the grandchild in its own session (escape).
		c := exec.Command(self, "sleep")
		c.Env = []string{helperEnv}
		c.Stdout = os.Stdout
		if args[0] == "escape" {
			c.SysProcAttr = newSessionAttr()
		}
		if err := c.Start(); err != nil {
			return 102
		}
		fmt.Println(c.Process.Pid)
		// The pid file in the working directory tells a test the
		// grandchild is up (written then renamed, so a reader never sees
		// a partial file).
		pidTmp := helperPidFile + ".tmp"
		if os.WriteFile(pidTmp, []byte(strconv.Itoa(c.Process.Pid)), 0o600) == nil {
			_ = os.Rename(pidTmp, helperPidFile)
		}
		if args[0] == "grandchild" {
			time.Sleep(time.Hour)
		}
	case "spawn":
		n, _ := strconv.Atoi(args[1])
		for i := 0; i < n; i++ {
			c := exec.Command(self, "sleep")
			c.Env = []string{helperEnv}
			if err := c.Start(); err != nil {
				return 103
			}
		}
		time.Sleep(time.Hour)
	case "limits":
		// Print this process's own rlimits as its first act: a cap applied
		// after the start (prlimit) could not be guaranteed to show here.
		for _, l := range ownLimits() {
			fmt.Println(l)
		}
	case "spin":
		for i := 0; ; i++ {
			_ = i * i
		}
	case "bigfile":
		f, err := os.Create(args[1])
		if err != nil {
			return 105
		}
		chunk := make([]byte, 64<<10)
		for n := 0; n < 4<<20; n += len(chunk) {
			if _, err := f.Write(chunk); err != nil {
				fmt.Println("write stopped at", n, err)
				return 3
			}
		}
		fmt.Println("wrote all")
	case "alloc":
		mb, _ := strconv.Atoi(args[1])
		b := make([]byte, mb<<20)
		for i := 0; i < len(b); i += 4096 {
			b[i] = 1
		}
		fmt.Println(len(b))
	default:
		return 104
	}
	return 0
}
