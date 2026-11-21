package secreachsvc

import (
	"reflect"
	"testing"
	"testing/fstest"
)

func TestFindGoMods(t *testing.T) {
	fsys := fstest.MapFS{
		"go.mod":                    {Data: []byte("module a\n")},
		"tools/go.mod":              {Data: []byte("module a/tools\n")},
		"vendor/x/go.mod":           {Data: []byte("module x\n")},
		"testdata/m/go.mod":         {Data: []byte("module m\n")},
		".git/go.mod":               {Data: []byte("module g\n")},
		"_old/go.mod":               {Data: []byte("module o\n")},
		"web/node_modules/p/go.mod": {Data: []byte("module p\n")},
		"cmd/main.go":               {Data: []byte("package main\n")},
	}
	got, trunc := FindGoMods(fsys, GoModLimits{})
	if want := []string{"go.mod", "tools/go.mod"}; !reflect.DeepEqual(got, want) || trunc {
		t.Errorf("FindGoMods = %v, %v; want %v, false", got, trunc, want)
	}
	got, trunc = FindGoMods(fsys, GoModLimits{MaxMods: 1})
	if len(got) != 1 || !trunc {
		t.Errorf("capped FindGoMods = %v, %v; want one, truncated", got, trunc)
	}
}
