package main

import "testing"

func TestGUIInstanceImage(t *testing.T) {
	for in, want := range map[string]string{
		`C:\Users\u\AppData\Local\Programs\Microsoft VS Code\Code.exe`: "Code.exe",
		`C:/Program Files/JetBrains/IDEA/bin/idea64.EXE`:               "idea64.EXE",
		`C:\Users\u\AppData\Roaming\npm\code.cmd`:                      "",
		"/usr/bin/code": "",
		"":              "",
	} {
		if got := guiInstanceImage(in); got != want {
			t.Errorf("guiInstanceImage(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGUIBundleExecDir(t *testing.T) {
	for in, want := range map[string]string{
		"/Applications/Visual Studio Code.app":                                 "/Applications/Visual Studio Code.app/Contents/MacOS/",
		"/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code": "/Applications/Visual Studio Code.app/Contents/MacOS/",
		"/Users/u/Applications/IntelliJ IDEA.app/Contents/MacOS/idea":          "/Users/u/Applications/IntelliJ IDEA.app/Contents/MacOS/",
		"/usr/local/bin/code": "",
	} {
		if got := guiBundleExecDir(in); got != want {
			t.Errorf("guiBundleExecDir(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGUIInstanceRunningEmptyBin(t *testing.T) {
	if guiInstanceRunning("") || guiInstanceRunning("   ") {
		t.Fatal("an empty launch target is never a running instance")
	}
}
