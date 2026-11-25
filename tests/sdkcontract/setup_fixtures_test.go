package sdkcontract

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/platformcontract"
	"github.com/marmutapp/superbased-observer/internal/sdkkeygrant"
)

// setupFixture is one exchange of sdk/contract/fixtures/setup (SDK quickstart
// plan section 4; onboarding-v2-connect-flow.md section 13).
type setupFixture struct {
	Doc     string `json:"_doc"`
	Method  string `json:"method"`
	URL     string `json:"url"`
	Request struct {
		Headers map[string]string `json:"headers"`
		Body    json.RawMessage   `json:"body"`
	} `json:"request"`
	Responses map[string]struct {
		Status  int               `json:"status"`
		Headers map[string]string `json:"headers"`
		Body    json.RawMessage   `json:"body"`
	} `json:"responses"`
}

func setupDir() string { return filepath.Join("..", "..", "sdk", "contract", "fixtures", "setup") }

func readSetupFixture(t *testing.T, name string, v any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(setupDir(), name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

// TestSetupFixturesShape: every exchange parses, names a method and an https
// URL, and every response has a status and an object (or null) body.
func TestSetupFixturesShape(t *testing.T) {
	for _, name := range []string{"connect-create.json", "connect-poll.json", "grant-redeem.json", "key-revoke.json"} {
		var f setupFixture
		readSetupFixture(t, name, &f)
		if f.Doc == "" || (f.Method != "GET" && f.Method != "POST") || !strings.HasPrefix(f.URL, "https://") || len(f.Responses) == 0 {
			t.Errorf("%s: incomplete exchange", name)
		}
		for k, r := range f.Responses {
			if r.Status < 200 || r.Status > 599 || len(r.Body) == 0 || (r.Body[0] != '{' && string(r.Body) != "null") {
				t.Errorf("%s %s: status %d body %s", name, k, r.Status, r.Body)
			}
			if r.Status == 429 && r.Headers["Retry-After"] == "" {
				t.Errorf("%s %s: a 429 without Retry-After", name, k)
			}
		}
	}
}

// fakes is fixtures/setup/secrecy-fakes.json.
type fakes struct {
	SDKKey       string `json:"sdk_key"`
	SDKKeySecret string `json:"sdk_key_secret"`
	DeviceCode   string `json:"device_code"`
	RedeemSecret string `json:"redeem_secret"`
	KeyGrant     string `json:"key_grant"`
}

// TestSetupFixturesAgreeWithTheGrantPackage: the redeem fixture's grant is a
// real key grant under internal/sdkkeygrant's TEST-ONLY vector key, the
// create's redeem_hash is the hash of the redeem secret the redeem sends, the
// poll delivers that grant, and the minted body is the member mint's own
// shape plus dashboard_url.
func TestSetupFixturesAgreeWithTheGrantPackage(t *testing.T) {
	var fk fakes
	readSetupFixture(t, "secrecy-fakes.json", &fk)

	var vec struct {
		PublicKey string `json:"public_key"`
		Valid     []struct {
			Token string `json:"token"`
			Now   int64  `json:"now"`
		} `json:"valid"`
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "sdkkeygrant", "testdata", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &vec); err != nil {
		t.Fatal(err)
	}
	pub, err := base64.RawURLEncoding.DecodeString(vec.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("vector public key: %v", err)
	}
	claims, err := sdkkeygrant.Verify(fk.KeyGrant, sdkkeygrant.Facts{
		Keys: platformcontract.KeySet{platformcontract.NewDocumentKey(pub)}, Now: time.Unix(vec.Valid[0].Now, 0),
	})
	if err != nil {
		t.Fatalf("the fixture grant does not verify under the vector key: %v", err)
	}
	if claims.RedeemHash != sdkkeygrant.RedeemHash(fk.RedeemSecret) || !sdkkeygrant.RedeemSecretValid(fk.RedeemSecret) {
		t.Fatal("the fixture redeem secret does not hash to the grant's redeem_hash")
	}

	var create setupFixture
	readSetupFixture(t, "connect-create.json", &create)
	var cbody map[string]any
	if err := json.Unmarshal(create.Request.Body, &cbody); err != nil {
		t.Fatal(err)
	}
	if cbody["purpose"] != "sdk_key" || cbody["redeem_hash"] != claims.RedeemHash || cbody["device_public_key"] != nil {
		t.Fatalf("create body %v", cbody)
	}
	var created struct {
		RequestID  string `json:"request_id"`
		DeviceCode string `json:"device_code"`
	}
	if err := json.Unmarshal(create.Responses["created"].Body, &created); err != nil {
		t.Fatal(err)
	}
	if created.RequestID != claims.RequestID || created.DeviceCode != fk.DeviceCode || len(fk.DeviceCode) != 43 {
		t.Fatalf("created %+v", created)
	}

	var poll setupFixture
	readSetupFixture(t, "connect-poll.json", &poll)
	if poll.Request.Headers["Authorization"] != "Bearer "+fk.DeviceCode || !strings.HasSuffix(poll.URL, "/"+claims.RequestID) {
		t.Fatal("the poll is not bearer-authenticated with the device code for this request")
	}
	var approved struct {
		KeyGrant string `json:"key_grant"`
		Target   struct {
			OrgID     string `json:"org_id"`
			Slug      string `json:"slug"`
			ServerURL string `json:"server_url"`
			Ready     bool   `json:"ready"`
		} `json:"target"`
		SignIn      any `json:"sign_in"`
		AttachGrant any `json:"attach_grant"`
	}
	if err := json.Unmarshal(poll.Responses["approved_with_grant"].Body, &approved); err != nil {
		t.Fatal(err)
	}
	if approved.KeyGrant != fk.KeyGrant || approved.Target.OrgID != claims.OrgID || approved.Target.Slug != claims.Slug || !approved.Target.Ready || approved.SignIn != nil || approved.AttachGrant != nil {
		t.Fatalf("approved poll %+v", approved)
	}
	for k, r := range poll.Responses {
		if strings.Contains(string(r.Body), `"sign_in"`) || strings.Contains(string(r.Body), `"attach_grant"`) {
			t.Errorf("poll %s carries a sign-in or an attach grant", k)
		}
	}

	var redeem setupFixture
	readSetupFixture(t, "grant-redeem.json", &redeem)
	var rbody struct {
		KeyGrant     string `json:"key_grant"`
		RedeemSecret string `json:"redeem_secret"`
	}
	if err := json.Unmarshal(redeem.Request.Body, &rbody); err != nil {
		t.Fatal(err)
	}
	if rbody.KeyGrant != fk.KeyGrant || rbody.RedeemSecret != fk.RedeemSecret || !strings.HasPrefix(redeem.URL, approved.Target.ServerURL+"/") {
		t.Fatal("the redeem does not carry the delivered grant and secret to the target host")
	}
	// The minted body is orgcontract.SDKCredentialMinted (every field it
	// names) plus dashboard_url and the optional plan_refusal.
	var minted map[string]json.RawMessage
	if err := json.Unmarshal(redeem.Responses["minted"].Body, &minted); err != nil {
		t.Fatal(err)
	}
	var typed orgcontract.SDKCredentialMinted
	if err := json.Unmarshal(redeem.Responses["minted"].Body, &typed); err != nil {
		t.Fatal(err)
	}
	if typed.Credential != fk.SDKKey || typed.KeyID+"."+fk.SDKKeySecret != fk.SDKKey || typed.GatewayURL == "" || typed.ExpiresAt == "" {
		t.Fatalf("minted %+v", typed)
	}
	back, _ := json.Marshal(typed)
	var round map[string]json.RawMessage
	_ = json.Unmarshal(back, &round)
	for k := range round {
		if _, ok := minted[k]; !ok && k != "environment_id" {
			t.Errorf("minted fixture lacks orgcontract.SDKCredentialMinted field %q", k)
		}
	}
	for k := range minted {
		if _, ok := round[k]; !ok && k != "dashboard_url" {
			t.Errorf("minted fixture field %q is neither SDKCredentialMinted's nor dashboard_url", k)
		}
	}
	if _, ok := minted["dashboard_url"]; !ok {
		t.Error("minted fixture lacks dashboard_url")
	}

	var file struct {
		Lines []string `json:"lines"`
	}
	readSetupFixture(t, "sdk-credential-file.json", &file)
	if len(file.Lines) == 0 || file.Lines[0] != fk.SDKKey || len(strings.Join(file.Lines, "\n"))+1 > 4096 {
		t.Fatalf("the SDK-held file %v does not start with the minted key", file.Lines)
	}
}
