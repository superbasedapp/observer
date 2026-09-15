package aigateway

import "testing"

func TestSubstringMarkers(t *testing.T) {
	tests := []struct {
		name    string
		markers []string
		input   string
		want    ScanClass
	}{
		{"no markers is clean", nil, "anything at all", ScanClean},
		{"blank markers ignored", []string{"", "  "}, "anything", ScanClean},
		{"exact hit critical", []string{"EXFIL-CANARY"}, "payload EXFIL-CANARY here", ScanCritical},
		{"case-insensitive hit", []string{"Secret-Prefix"}, "value=secret-prefix-9", ScanCritical},
		{"miss is clean", []string{"nope"}, "clean body", ScanClean},
		{"one of several", []string{"a", "codename-zeus"}, "mentions codename-zeus", ScanCritical},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fn := SubstringMarkers(tc.markers)
			var got ScanClass
			if fn != nil {
				got = fn([]byte(tc.input))
			}
			if got != tc.want {
				t.Errorf("SubstringMarkers(%v)(%q) = %v, want %v", tc.markers, tc.input, got, tc.want)
			}
		})
	}
}

func TestFuncGuardScannerNilSidesClean(t *testing.T) {
	var s FuncGuardScanner // both funcs nil
	if s.ScanRequest([]byte("x")) != ScanClean {
		t.Error("nil Request should classify clean")
	}
	if s.ScanChunk([]byte("x")) != ScanClean {
		t.Error("nil Chunk should classify clean")
	}
}

func TestNewMarkerEgressScanner(t *testing.T) {
	// No markers → an honest NoopGuardScanner, not a silent pass-through Func.
	if _, ok := NewMarkerEgressScanner(nil).(NoopGuardScanner); !ok {
		t.Fatal("empty marker set should yield NoopGuardScanner")
	}
	s := NewMarkerEgressScanner([]string{"boom"})
	if s.ScanRequest([]byte("this will boom")) != ScanCritical {
		t.Error("request with marker should be critical")
	}
	if AbortOnScan(s.ScanChunk([]byte("kaboom later"))) != true {
		t.Error("chunk with marker should abort")
	}
	if s.ScanRequest([]byte("harmless")) != ScanClean {
		t.Error("request without marker should be clean")
	}
}
