package powerstate

import "testing"

func TestClassifyTable(t *testing.T) {
	t.Parallel()
	bat := func(status string) Supply { return Supply{Type: "Battery", Status: status} }
	mains := func(online string) Supply { return Supply{Type: "Mains", Online: online} }
	cases := []struct {
		name string
		ss   []Supply
		want State
	}{
		{"no supplies (desktop, container)", nil, AC},
		{"mains only", []Supply{mains("1")}, AC},
		{"laptop on mains", []Supply{mains("1"), bat("Charging")}, AC},
		{"laptop on battery", []Supply{mains("0"), bat("Discharging")}, Battery},
		{"battery only, discharging", []Supply{bat("Discharging")}, Battery},
		{"USB power online", []Supply{{Type: "USB", Online: "1"}, bat("Discharging")}, AC},
		{"full battery, no mains row", []Supply{bat("Full")}, AC},
		{"not charging (held at a threshold)", []Supply{bat("Not charging")}, AC},
		{"battery state unknown", []Supply{bat("Unknown")}, Unknown},
		{"mains offline, battery state unknown", []Supply{mains("0"), bat("")}, Unknown},
		// Peripheral supplies (sysfs scope=Device) are not this machine's.
		{"desktop with a discharging mouse battery", []Supply{{Type: "Battery", Status: "Discharging", Scope: "Device"}}, AC},
		{"desktop on mains, headset discharging", []Supply{mains("1"), {Type: "Battery", Status: "Discharging", Scope: "Device"}}, AC},
		{"UPS reporting over HID, discharging", []Supply{{Type: "Battery", Status: "Discharging", Scope: "device"}}, AC},
		{"laptop on battery, mouse charging", []Supply{mains("0"), bat("Discharging"), {Type: "Battery", Status: "Charging", Scope: "Device"}}, Battery},
		{"device mains online does not mean mains", []Supply{{Type: "Mains", Online: "1", Scope: "Device"}, bat("Discharging")}, Battery},
		{"system-scoped battery still counts", []Supply{{Type: "Battery", Status: "Discharging", Scope: "System"}}, Battery},
	}
	for _, tc := range cases {
		if got := Classify(tc.ss); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestClassifyWindows(t *testing.T) {
	t.Parallel()
	cases := []struct {
		ac, flag byte
		want     State
	}{
		{1, 8, AC},
		{0, 0, Battery},
		{255, 0, Unknown},
		{255, 128, AC},
		{0, 128, AC},
	}
	for _, tc := range cases {
		if got := classifyWindows(tc.ac, tc.flag); got != tc.want {
			t.Errorf("ac %d flag %d: %s, want %s", tc.ac, tc.flag, got, tc.want)
		}
	}
}
