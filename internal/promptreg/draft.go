package promptreg

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"
)

// Draft is a create-version request as it arrives (the admin route body, the
// machine route body, the CLI).
type Draft struct {
	Type          Type            `json:"type"`
	Prompt        json.RawMessage `json:"prompt"`
	Config        json.RawMessage `json:"config,omitempty"`
	CommitMessage string          `json:"commit_message,omitempty"`
	// Labels are moved onto the new version in the same change.
	Labels []string `json:"labels,omitempty"`
}

// NewVersion validates d and builds version number next of prompt name in
// canonical form. existing is the type of the prompt's first version ("" for
// a new prompt): a version of another type is ErrTypeMismatch.
func NewVersion(name string, next int, existing Type, d Draft, actor string, at time.Time) (Version, error) {
	if !ValidName(name) {
		return Version{}, badRequest("a prompt name is 1 to %d characters of letters, digits, '.', '_' and '-', starting with a letter or digit", MaxNameBytes)
	}
	if next < 1 {
		return Version{}, badRequest("version numbers start at 1")
	}
	t := Type(strings.TrimSpace(string(d.Type)))
	if t == "" {
		t = TypeText
	}
	prompt, err := canonicalPrompt(t, d.Prompt)
	if err != nil {
		return Version{}, err
	}
	if existing != "" && existing != t {
		return Version{}, ErrTypeMismatch
	}
	config, err := canonicalConfig(d.Config)
	if err != nil {
		return Version{}, err
	}
	if len(d.CommitMessage) > MaxCommitMessageBytes || !utf8.ValidString(d.CommitMessage) {
		return Version{}, badRequest("commit_message is at most %d bytes of UTF-8", MaxCommitMessageBytes)
	}
	for _, l := range d.Labels {
		if !ValidLabel(l) {
			return Version{}, badRequest("unknown label %q; the labels are %s", l, strings.Join(Labels(), ", "))
		}
	}
	v := Version{
		Name: name, Version: next, Type: t, Prompt: prompt, Config: config,
		CommitMessage: d.CommitMessage, CreatedBy: actor, CreatedAt: at.UTC().Truncate(time.Second),
	}
	v.Digest = ContentDigest(v)
	return v, nil
}

// DraftLabels returns d's labels, de-duplicated, in vocabulary order.
func DraftLabels(d Draft) []string {
	want := map[string]bool{}
	for _, l := range d.Labels {
		want[l] = true
	}
	out := []string{}
	for _, l := range Labels() {
		if want[l] {
			out = append(out, l)
		}
	}
	return out
}

// canonicalPrompt validates a body of type t and re-encodes it canonically.
func canonicalPrompt(t Type, raw json.RawMessage) ([]byte, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, badRequest("prompt is required")
	}
	switch t {
	case TypeText:
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, badRequest("a text prompt is a JSON string")
		}
		if err := checkContent(s, len(s)); err != nil {
			return nil, err
		}
		return marshal(s)
	case TypeChat:
		// A chat body may also arrive as JSON text holding the array (a form
		// field, the admin assistant's string-typed argument).
		if t := bytes.TrimSpace(raw); len(t) > 0 && t[0] == '"' {
			var inner string
			if err := json.Unmarshal(t, &inner); err == nil {
				raw = json.RawMessage(inner)
			}
		}
		var msgs []Message
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&msgs); err != nil {
			return nil, badRequest("a chat prompt is a JSON array of {\"role\", \"content\"} strings")
		}
		if len(msgs) == 0 || len(msgs) > MaxMessages {
			return nil, badRequest("a chat prompt has 1 to %d messages", MaxMessages)
		}
		total := 0
		for i, m := range msgs {
			if !chatRoles[m.Role] {
				return nil, badRequest("message %d: role %q is not one of %s", i, m.Role, strings.Join(ChatRoles(), ", "))
			}
			total += len(m.Content)
			if err := checkContent(m.Content, total); err != nil {
				return nil, err
			}
		}
		return marshal(msgs)
	}
	return nil, badRequest("type is %q or %q", TypeText, TypeChat)
}

func checkContent(s string, total int) error {
	if total > MaxBodyBytes {
		return badRequest("a prompt body is at most %d bytes", MaxBodyBytes)
	}
	if !utf8.ValidString(s) {
		return badRequest("a prompt body is UTF-8 text")
	}
	return nil
}

// canonicalConfig validates an optional config object and compacts it.
func canonicalConfig(raw json.RawMessage) ([]byte, error) {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || bytes.Equal(t, []byte("null")) {
		return []byte("{}"), nil
	}
	if t[0] != '{' || !json.Valid(t) {
		return nil, badRequest("config is a JSON object")
	}
	var b bytes.Buffer
	if err := json.Compact(&b, t); err != nil {
		return nil, badRequest("config is a JSON object")
	}
	if b.Len() > MaxConfigBytes {
		return nil, badRequest("config is at most %d bytes", MaxConfigBytes)
	}
	return b.Bytes(), nil
}

// marshal is the one JSON encoder of this package: no HTML escaping (prompts
// are full of <tags>), no trailing newline.
func marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// contentDoc is what ContentDigest hashes.
type contentDoc struct {
	Name    string          `json:"name"`
	Version int             `json:"version"`
	Type    Type            `json:"type"`
	Prompt  json.RawMessage `json:"prompt"`
	Config  json.RawMessage `json:"config"`
}

// ContentDigest is "sha256:" + the hex SHA-256 of the version's canonical
// content (name, version, type, prompt, config). Labels are not content: the
// digest is stable for the life of the version.
func ContentDigest(v Version) string {
	b, err := marshal(contentDoc{Name: v.Name, Version: v.Version, Type: v.Type, Prompt: v.Prompt, Config: orEmpty(v.Config)})
	if err != nil {
		// Unreachable for a canonical version; never a silent empty digest.
		return "sha256:invalid"
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func orEmpty(b []byte) json.RawMessage {
	if len(bytes.TrimSpace(b)) == 0 {
		return json.RawMessage("{}")
	}
	return json.RawMessage(b)
}
