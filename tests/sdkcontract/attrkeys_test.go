package sdkcontract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/genaiattr"
	"github.com/marmutapp/superbased-observer/internal/otelident"
)

// attrKeys is sdk/contract/sdk-attribute-keys.json: every span-attribute key
// the superbased SDKs write (sdk-api-surface.md section 9).
type attrKeys struct {
	SemconvCommit         string         `json:"semconv_commit"`
	Vocabulary            []string       `json:"vocabulary"`
	VocabularyPrefixes    []string       `json:"vocabulary_prefixes"`
	SDKOwned              []string       `json:"sdk_owned"`
	PendingVocabulary     []string       `json:"pending_vocabulary"`
	ContentFields         []string       `json:"content_fields"`
	ContentKeys           []string       `json:"content_keys"`
	ContentPrefixes       []string       `json:"content_prefixes"`
	ContentPrefixExemptSx []string       `json:"content_prefix_exempt_suffixes"`
	ExtraContentPrefixes  []string       `json:"extra_content_prefixes"`
	Limits                map[string]int `json:"limits"`
}

func loadAttrKeys(t *testing.T) attrKeys {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "sdk", "contract", "sdk-attribute-keys.json"))
	if err != nil {
		t.Fatalf("read sdk-attribute-keys.json: %v", err)
	}
	var k attrKeys
	if err := json.Unmarshal(raw, &k); err != nil {
		t.Fatalf("decode sdk-attribute-keys.json: %v", err)
	}
	if len(k.Vocabulary) == 0 || len(k.ContentFields) == 0 {
		t.Fatal("sdk-attribute-keys.json lists no vocabulary or content fields")
	}
	return k
}

// goVocabulary is every key the Go vocabulary knows: the genaiattr table,
// its request parameters and every otelident identity list.
func goVocabulary() map[string]bool {
	out := map[string]bool{}
	for _, k := range genaiattr.Table() {
		out[k.Name] = true
	}
	for k := range genaiattr.ParamKeys() {
		out[k] = true
	}
	for _, list := range [][]string{
		otelident.TenantKeys, otelident.UserKeys, otelident.SessionKeys, otelident.ServiceKeys,
		otelident.EnvironmentKeys, otelident.ReleaseKeys, otelident.TagKeys, otelident.MetadataKeys,
	} {
		for _, k := range list {
			out[k] = true
		}
	}
	return out
}

// TestSDKKeysAreVocabulary: every key the SDKs write as mapping vocabulary is
// a key some Go mapper reads, so no SDK attribute is silently ignored.
func TestSDKKeysAreVocabulary(t *testing.T) {
	k := loadAttrKeys(t)
	vocab := goVocabulary()
	for _, key := range k.Vocabulary {
		if !vocab[key] {
			t.Errorf("SDK vocabulary key %q is not in internal/genaiattr or internal/otelident", key)
		}
	}
	for _, p := range k.VocabularyPrefixes {
		found := false
		for _, mp := range otelident.MetadataPrefixes {
			if mp == p {
				found = true
			}
		}
		if !found {
			t.Errorf("SDK vocabulary prefix %q is not an otelident.MetadataPrefixes entry", p)
		}
	}
	for _, key := range k.SDKOwned {
		if vocab[key] {
			t.Errorf("SDK-owned key %q is mapping vocabulary; list it under vocabulary", key)
		}
		if !strings.HasPrefix(key, "sbo.") {
			t.Errorf("SDK-owned key %q must be in the sbo. namespace", key)
		}
	}
	for _, key := range k.PendingVocabulary {
		if !strings.HasPrefix(key, "sbo.") {
			t.Errorf("pending vocabulary key %q must be in the sbo. namespace", key)
		}
		if vocab[key] {
			t.Logf("pending key %q is now Go vocabulary: move it to vocabulary in sdk-attribute-keys.json", key)
		}
	}
	if k.SemconvCommit != genaiattr.SemconvCommit {
		t.Errorf("SDK semconv pin %s != genaiattr.SemconvCommit %s", k.SemconvCommit, genaiattr.SemconvCommit)
	}
}

// TestSDKContentKeysMatchGenaiattr: the keys the SDKs mask, clip and drop
// (capture_content, mask, max_content_chars) are exactly genaiattr's content
// fields, and the indexed prefixes are its message lists.
func TestSDKContentKeysMatchGenaiattr(t *testing.T) {
	k := loadAttrKeys(t)
	want := map[string]bool{}
	for _, f := range k.ContentFields {
		keys := genaiattr.Keys(genaiattr.Field(f))
		if len(keys) == 0 {
			t.Errorf("content field %q has no keys in genaiattr", f)
		}
		for _, key := range keys {
			want[key] = true
		}
	}
	got := map[string]bool{}
	for _, key := range k.ContentKeys {
		got[key] = true
	}
	for key := range want {
		if !got[key] {
			t.Errorf("genaiattr content key %q is missing from the SDK content keys", key)
		}
	}
	for key := range got {
		if !want[key] {
			t.Errorf("SDK content key %q is not a genaiattr content-field key", key)
		}
	}
	var wantPrefixes []string
	for _, l := range append(append([]genaiattr.IndexedList{}, genaiattr.IndexedInput...), genaiattr.IndexedOutput...) {
		wantPrefixes = append(wantPrefixes, l.Prefix+".")
	}
	gotPrefixes := append([]string{}, k.ContentPrefixes...)
	sort.Strings(wantPrefixes)
	sort.Strings(gotPrefixes)
	if strings.Join(wantPrefixes, ",") != strings.Join(gotPrefixes, ",") {
		t.Errorf("content prefixes = %v, want genaiattr indexed lists %v", gotPrefixes, wantPrefixes)
	}
	exempt := func(suffix string) bool {
		for _, s := range k.ContentPrefixExemptSx {
			if strings.HasSuffix(suffix, s) {
				return true
			}
		}
		return false
	}
	for _, l := range append(append([]genaiattr.IndexedList{}, genaiattr.IndexedInput...), genaiattr.IndexedOutput...) {
		if !exempt(l.Role) {
			t.Errorf("indexed role suffix %q is not exempt from content rules", l.Role)
		}
		if exempt(l.Content) {
			t.Errorf("indexed content suffix %q is exempt from content rules", l.Content)
		}
	}
	for _, p := range k.ExtraContentPrefixes {
		for _, key := range genaiattr.Table() {
			if strings.HasPrefix(key.Name, p) {
				t.Errorf("genaiattr now maps %q under the SDK's extra content prefix %q: move it to the content fields", key.Name, p)
			}
		}
	}
	if !exempt(genaiattr.IndexedFinishReason) {
		t.Errorf("finish-reason suffix %q is not exempt from content rules", genaiattr.IndexedFinishReason)
	}
}

// TestSDKLimitsMatchOtelident: the SDKs clamp identity values with the same
// bounds ingest applies.
func TestSDKLimitsMatchOtelident(t *testing.T) {
	k := loadAttrKeys(t)
	want := map[string]int{
		"max_value_len":          otelident.MaxValueLen,
		"max_tags":               otelident.MaxTags,
		"max_tag_len":            otelident.MaxTagLen,
		"max_metadata_keys":      otelident.MaxMetadataKeys,
		"max_metadata_key_len":   otelident.MaxMetadataKeyLen,
		"max_metadata_value_len": otelident.MaxMetadataValueLen,
	}
	for name, v := range want {
		if got, ok := k.Limits[name]; !ok || got != v {
			t.Errorf("limit %s = %d (present %v), want otelident %d", name, got, ok, v)
		}
	}
}
