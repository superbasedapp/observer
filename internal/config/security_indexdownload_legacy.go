package config

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// [security.deps].index_download was a string on the plan branch before
// it became the bool off switch (operator ruling PT-19, lane sec-deps4):
// "always" (the default) or "after_consent". A config that still says so
// must keep loading, or the daemon would not start (lane sec-deps4 audit
// finding 8), so the loader rewrites the old string forms to the bool
// before decoding. The words that mean on and off are a table, walked
// once; a word outside it is left alone and fails to decode as before.
// "after_consent" reads off: it held the download back, and the off
// switch is the closer of the two new values to that.

// legacyIndexDownloadWords maps each old string form to the bool it means.
var legacyIndexDownloadWords = map[string]bool{
	"always": true, "on": true, "true": true,
	"never": false, "off": false, "false": false, "after_consent": false,
}

// legacyIndexDownloadLine finds an index_download assignment to a quoted
// string: the bare key under [security.deps], or a dotted key reaching it
// (deps.index_download under [security], security.deps.index_download at
// the top). index_download names no other key in the schema.
var legacyIndexDownloadLine = regexp.MustCompile(`(?m)^([ \t]*(?:[A-Za-z0-9_-]+[ \t]*\.[ \t]*)*index_download[ \t]*=[ \t]*)(?:"([^"\n]*)"|'([^'\n]*)')`)

// normalizeLegacyIndexDownload returns body with an old string form of
// index_download rewritten to its bool. A body that does not set the key
// to a string comes back unchanged.
func normalizeLegacyIndexDownload(body []byte) []byte {
	if !bytes.Contains(body, []byte("index_download")) {
		return body
	}
	var probe struct {
		Security struct {
			Deps struct {
				IndexDownload any `toml:"index_download"`
			} `toml:"deps"`
		} `toml:"security"`
	}
	if _, err := toml.Decode(string(body), &probe); err != nil {
		return body
	}
	if _, isString := probe.Security.Deps.IndexDownload.(string); !isString {
		return body
	}
	return legacyIndexDownloadLine.ReplaceAllFunc(body, func(m []byte) []byte {
		sub := legacyIndexDownloadLine.FindSubmatch(m)
		word := string(sub[2])
		if len(sub[3]) > 0 {
			word = string(sub[3])
		}
		on, ok := legacyIndexDownloadWords[strings.ToLower(strings.TrimSpace(word))]
		if !ok {
			return m
		}
		return append(append([]byte(nil), sub[1]...), strconv.FormatBool(on)...)
	})
}
