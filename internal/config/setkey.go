package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// This file implements the dotted-key setter behind `observer config
// set` (P3.3): one generic walk over toml struct tags serving both
// the global config.toml (full Config) and repo-local project
// overlay files (the allow-listed projectOverlayDoc). Writes go
// through the same atomic .bak helper as every other config write —
// one owner, another front door.

// SetConfigKey sets a dotted TOML key (e.g.
// "compression.conversation.target_ratio" or
// "profiles.by_tool.cline") on cfg, resolving path segments against
// toml struct tags. Map-valued leaves (map[string]string) consume the
// final segment as the entry key. The value string is parsed per the
// destination type; type mismatches and unknown keys error with the
// failing segment named.
func SetConfigKey(cfg *Config, dotted, value string) error {
	return setStructKey(reflect.ValueOf(cfg).Elem(), strings.Split(dotted, "."), dotted, value)
}

// UpdateProjectOverlay sets a dotted key in <root>/.observer/
// config.toml, creating the file when absent. Only allow-listed keys
// are writable: the profiles table and compression parameters. The
// write goes through the shared .bak + atomic-rename path.
func UpdateProjectOverlay(root, dotted, value string) error {
	seg0 := strings.SplitN(dotted, ".", 2)[0]
	if seg0 != "profiles" && seg0 != "compression" {
		return fmt.Errorf("config: project files accept only profiles.* and compression.* keys (got %q) — daemon-level keys live in the global config.toml", dotted)
	}
	path := filepath.Join(root, ProjectOverlayFilename)
	var doc projectOverlayDoc
	if body, err := os.ReadFile(path); err == nil {
		if err := toml.Unmarshal(body, &doc); err != nil {
			return fmt.Errorf("config: existing %s does not parse; fix it before setting keys: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("config: read %s: %w", path, err)
	}
	if err := setStructKey(reflect.ValueOf(&doc).Elem(), strings.Split(dotted, "."), dotted, value); err != nil {
		return err
	}
	return writeTOMLAtomic(path, doc)
}

// setStructKey walks segs against v's toml tags and sets the leaf
// from value. dotted is carried for error messages only.
func setStructKey(v reflect.Value, segs []string, dotted, value string) error {
	if len(segs) == 0 {
		return fmt.Errorf("config: empty key")
	}
	seg := segs[0]
	switch v.Kind() {
	case reflect.Struct:
		t := v.Type()
		for i := range t.NumField() {
			tag := strings.Split(t.Field(i).Tag.Get("toml"), ",")[0]
			if tag != seg {
				continue
			}
			field := v.Field(i)
			if len(segs) == 1 {
				return setLeaf(field, dotted, value)
			}
			return setStructKey(field, segs[1:], dotted, value)
		}
		return fmt.Errorf("config: unknown key segment %q in %q", seg, dotted)
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String || v.Type().Elem().Kind() != reflect.String {
			return fmt.Errorf("config: %q points into an unsupported map type", dotted)
		}
		if len(segs) != 1 {
			return fmt.Errorf("config: map entry %q takes exactly one trailing segment", dotted)
		}
		if v.IsNil() {
			v.Set(reflect.MakeMap(v.Type()))
		}
		v.SetMapIndex(reflect.ValueOf(seg), reflect.ValueOf(value))
		return nil
	default:
		return fmt.Errorf("config: key %q descends past a leaf at %q", dotted, seg)
	}
}

// setLeaf parses value into field per its kind. Supported leaves:
// string, bool, ints, floats, []string (comma-separated, items
// trimmed, "" = empty list), and map[string]string handled by the
// caller's map branch.
func setLeaf(field reflect.Value, dotted, value string) error {
	switch field.Kind() {
	case reflect.String:
		field.SetString(value)
	case reflect.Bool:
		b, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("config: %q wants true/false, got %q", dotted, value)
		}
		field.SetBool(b)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("config: %q wants an integer, got %q", dotted, value)
		}
		field.SetInt(n)
	case reflect.Float32, reflect.Float64:
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return fmt.Errorf("config: %q wants a number, got %q", dotted, value)
		}
		field.SetFloat(f)
	case reflect.Slice:
		if field.Type().Elem().Kind() != reflect.String {
			return fmt.Errorf("config: %q is an unsupported slice type", dotted)
		}
		var items []string
		if strings.TrimSpace(value) != "" {
			for _, it := range strings.Split(value, ",") {
				items = append(items, strings.TrimSpace(it))
			}
		}
		field.Set(reflect.ValueOf(items))
	case reflect.Map:
		return fmt.Errorf("config: %q is a table — set one entry (e.g. %s.anthropic)", dotted, dotted)
	default:
		return fmt.Errorf("config: %q is a table, not a settable value", dotted)
	}
	return nil
}
