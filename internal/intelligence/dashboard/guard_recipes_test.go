package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// Guard recipes (guard_recipes.go): the catalog GET mints the confirm token,
// the preview and the simulate replay are reads, and every write needs the
// token, keeps the files the service owns and refuses an unknown project.

// newGuardRecipeServer is a dashboard whose guard policy paths all sit in a
// temp dir, so nothing of the machine's own guard is read or written.
func newGuardRecipeServer(t *testing.T) (*Server, string, string) {
	t.Helper()
	dir := t.TempDir()
	slash := filepath.ToSlash
	body := "[guard]\nenabled = true\nmode = \"observe\"\n\n" +
		"[guard.rules]\nuser_policy = '" + slash(filepath.Join(dir, "guard-policy.toml")) + "'\n" +
		"trusted_project_dir = '" + slash(filepath.Join(dir, "guard-project-policies")) + "'\n" +
		"org_bundle = '" + slash(filepath.Join(dir, "org-policy-bundle.json")) + "'\n"
	s, cfgPath := newSecretTestServer(t, body)
	return s, cfgPath, dir
}

type guardRecipesState struct {
	Catalog []struct {
		Name string `json:"name"`
		Kind string `json:"kind"`
	} `json:"catalog"`
	Level        string          `json:"level"`
	Mode         string          `json:"mode"`
	Global       json.RawMessage `json:"global"`
	LevelDrift   string          `json:"level_drift"`
	TrustedLayer bool            `json:"trusted_layer"`
	ConfirmToken string          `json:"confirm_token"`
}

func getGuardRecipes(t *testing.T, s *Server) (guardRecipesState, *http.Cookie) {
	t.Helper()
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/guard/recipes", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/guard/recipes: %d %s", rr.Code, rr.Body.String())
	}
	var v guardRecipesState
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	var cookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == remoteConfirmCookie {
			cookie = c
		}
	}
	return v, cookie
}

func postGuardRecipe(t *testing.T, s *Server, path, body string, confirm bool) *httptest.ResponseRecorder {
	t.Helper()
	v, cookie := getGuardRecipes(t, s)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if confirm {
		req.Header.Set(remoteConfirmHeader, v.ConfirmToken)
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	return rr
}

func TestGuardRecipes_CatalogAndPreview(t *testing.T) {
	s, _, _ := newGuardRecipeServer(t)
	v, cookie := getGuardRecipes(t, s)
	if v.ConfirmToken == "" || cookie == nil {
		t.Fatal("the catalog GET mints the confirm token")
	}
	if !v.TrustedLayer || string(v.Global) != "null" || v.LevelDrift != "" {
		t.Fatalf("fresh state: %+v", v)
	}
	var names []string
	for _, r := range v.Catalog {
		names = append(names, r.Kind+":"+r.Name)
	}
	if got := strings.Join(names[:5], ","); got != "level:none,level:loose,level:balanced,level:strict,level:lockdown" {
		t.Fatalf("levels lead the catalog in strictness order: %s", got)
	}

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/guard/recipes/preview?level=balanced&scope=global", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("preview: %d %s", rr.Code, rr.Body.String())
	}
	var pv struct {
		ModeBefore string   `json:"mode_before"`
		ModeAfter  string   `json:"mode_after"`
		LevelAfter string   `json:"level_after"`
		Text       string   `json:"text"`
		Problems   []string `json:"problems"`
		Changes    []struct {
			RuleID string `json:"rule_id"`
		} `json:"changes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &pv); err != nil {
		t.Fatal(err)
	}
	if pv.ModeBefore != "observe" || pv.ModeAfter != "enforce" || pv.LevelAfter != "balanced" || len(pv.Problems) != 0 {
		t.Fatalf("balanced moves observe to enforce: %+v", pv)
	}
	if len(pv.Changes) == 0 || !strings.Contains(pv.Text, "# observer-guard-recipe: ") {
		t.Fatalf("the preview lists changes and carries the file: %d changes", len(pv.Changes))
	}

	for _, tc := range []struct {
		name, query string
		status      int
	}{
		{"nothing picked", "scope=global", http.StatusBadRequest},
		{"bad scope", "level=strict&scope=team", http.StatusBadRequest},
		{"unknown project", "level=strict&scope=project&project_root=/nowhere", http.StatusConflict},
		{"unknown recipe", "level=nosuch&scope=global", http.StatusBadRequest},
		{"remove with nothing applied", "remove=1&scope=global", http.StatusNotFound},
	} {
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/guard/recipes/preview?"+tc.query, nil))
		if rr.Code != tc.status {
			t.Errorf("%s: %d, want %d (%s)", tc.name, rr.Code, tc.status, rr.Body.String())
		}
	}
}

func TestGuardRecipes_ApplyRemove(t *testing.T) {
	s, cfgPath, dir := newGuardRecipeServer(t)
	recipeFile := filepath.Join(dir, "guard-policy.recipe.toml")

	if rr := postGuardRecipe(t, s, "/api/guard/recipes/apply", `{"level":"strict","scope":"global"}`, false); rr.Code != http.StatusForbidden {
		t.Fatalf("an apply without the confirm token is refused: %d", rr.Code)
	}
	if _, err := os.Stat(recipeFile); !os.IsNotExist(err) {
		t.Fatal("a refused apply writes nothing")
	}
	if rr := postGuardRecipe(t, s, "/api/guard/recipes/apply", `{"level":"strict","scope":"global","extra":1}`, true); rr.Code != http.StatusBadRequest {
		t.Fatalf("an unknown body field is refused: %d", rr.Code)
	}
	if rr := postGuardRecipe(t, s, "/api/guard/recipes/apply", `{"packs":["frontend"],"scope":"project","project_root":"/nowhere"}`, true); rr.Code != http.StatusConflict {
		t.Fatalf("an unknown project is refused: %d", rr.Code)
	}

	rr := postGuardRecipe(t, s, "/api/guard/recipes/apply", `{"level":"strict","packs":["frontend"],"scope":"global"}`, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", rr.Code, rr.Body.String())
	}
	var res struct {
		Applied         bool `json:"applied"`
		RestartRequired bool `json:"restart_required"`
		Result          struct {
			ConfigChanged bool `json:"config_changed"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !res.Applied || !res.RestartRequired || !res.Result.ConfigChanged {
		t.Fatalf("apply result: %s", rr.Body.String())
	}
	raw, err := os.ReadFile(recipeFile)
	if err != nil || !strings.Contains(string(raw), `"name":"strict"`) {
		t.Fatalf("the recipe file names the level: %v %s", err, raw)
	}
	v, _ := getGuardRecipes(t, s)
	if v.Level != "strict" || v.Mode != "enforce" || v.LevelDrift != "" {
		t.Fatalf("after apply: %+v", v)
	}

	// The replay compares the policy before and after the selection.
	sim := httptest.NewRecorder()
	s.Handler().ServeHTTP(sim, httptest.NewRequest(http.MethodGet, "/api/guard/simulate?hours=168&recipe=1&level=lockdown&scope=global", nil))
	if sim.Code != http.StatusOK || !strings.Contains(sim.Body.String(), `"recipe_replay"`) {
		t.Fatalf("simulate recipe=1: %d %s", sim.Code, sim.Body.String())
	}
	plain := httptest.NewRecorder()
	s.Handler().ServeHTTP(plain, httptest.NewRequest(http.MethodGet, "/api/guard/simulate?hours=168", nil))
	if strings.Contains(plain.Body.String(), "recipe_replay") {
		t.Fatal("a plain simulate carries no recipe replay")
	}

	rr = postGuardRecipe(t, s, "/api/guard/recipes/remove", `{"scope":"global"}`, true)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"removed":true`) {
		t.Fatalf("remove: %d %s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(recipeFile); !os.IsNotExist(err) {
		t.Fatal("remove deletes the recipe file")
	}
	v, _ = getGuardRecipes(t, s)
	if v.Level != "" || v.Mode != "observe" {
		t.Fatalf("remove puts the level and mode back: %+v", v)
	}
	cfg, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(cfg), "[guard.rules]") {
		t.Fatalf("the rest of config.toml is kept: %s", cfg)
	}
	rr = postGuardRecipe(t, s, "/api/guard/recipes/remove", `{"scope":"global"}`, true)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"removed":false`) {
		t.Fatalf("a second remove finds nothing: %d %s", rr.Code, rr.Body.String())
	}
}

func TestGuardRecipes_UserRecipes(t *testing.T) {
	s, _, dir := newGuardRecipeServer(t)
	mine := "name = \"mine\"\nkind = \"pack\"\ntitle = \"Mine\"\nsummary = \"My pack.\"\nversion = 1\n\n[[override]]\nrule = \"R-140\"\ndecision = \"deny\"\n"
	body, _ := json.Marshal(map[string]string{"name": "mine", "toml": mine})
	if rr := postGuardRecipe(t, s, "/api/guard/recipes/user", string(body), false); rr.Code != http.StatusForbidden {
		t.Fatalf("a save without the confirm token is refused: %d", rr.Code)
	}
	rr := postGuardRecipe(t, s, "/api/guard/recipes/user", string(body), true)
	if rr.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "guard-recipes", "mine.toml")); err != nil {
		t.Fatalf("the recipe lands in the guard-recipes dir: %v", err)
	}
	show := httptest.NewRecorder()
	s.Handler().ServeHTTP(show, httptest.NewRequest(http.MethodGet, "/api/guard/recipes/show?name=mine", nil))
	if show.Code != http.StatusOK || !strings.Contains(show.Body.String(), `"source":"user"`) {
		t.Fatalf("show: %d %s", show.Code, show.Body.String())
	}
	builtin, _ := json.Marshal(map[string]string{"name": "strict", "toml": strings.Replace(mine, `"mine"`, `"strict"`, 1)})
	if rr := postGuardRecipe(t, s, "/api/guard/recipes/user", string(builtin), true); rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a built-in name is refused: %d", rr.Code)
	}
	if rr := postGuardRecipe(t, s, "/api/guard/recipes/user/delete", `{"name":"strict"}`, true); rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a built-in recipe cannot be deleted: %d", rr.Code)
	}
	if rr := postGuardRecipe(t, s, "/api/guard/recipes/user/delete", `{"name":"mine"}`, true); rr.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "guard-recipes", "mine.toml")); !os.IsNotExist(err) {
		t.Fatal("delete removes the file")
	}
}

// TestGuardRecipes_RemoveRefusedWithProblems: a remove that would drop the
// person's own policy layer answers 422 with every problem and writes nothing.
func TestGuardRecipes_RemoveRefusedWithProblems(t *testing.T) {
	s, _, dir := newGuardRecipeServer(t)
	recipeFile := filepath.Join(dir, "guard-policy.recipe.toml")
	if rr := postGuardRecipe(t, s, "/api/guard/recipes/apply", `{"level":"lockdown","scope":"global"}`, true); rr.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", rr.Code, rr.Body.String())
	}
	own := "[[override]]\nrule = \"RC-LCK-01\"\ndecision = \"ask\"\n"
	if err := os.WriteFile(filepath.Join(dir, "guard-policy.toml"), []byte(own), 0o600); err != nil {
		t.Fatal(err)
	}
	rr := postGuardRecipe(t, s, "/api/guard/recipes/remove", `{"scope":"global"}`, true)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("remove: %d %s", rr.Code, rr.Body.String())
	}
	var res struct {
		Removed  bool     `json:"removed"`
		Problems []string `json:"problems"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil || res.Removed || len(res.Problems) == 0 {
		t.Fatalf("body: %v %s", err, rr.Body.String())
	}
	if _, err := os.Stat(recipeFile); err != nil {
		t.Fatal("a refused remove keeps the recipe file")
	}
}

// TestGuardSummary_CarriesPromptGuardPosture: the posture header can say
// what the prompt guard does beside the guard mode.
func TestGuardSummary_CarriesPromptGuardPosture(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		sidecar    string
		wantIndep  bool
		wantOrg    bool
	}{
		{"default acts on its own mode", "[guard]\nenabled = true\nmode = \"observe\"\n", "", true, false},
		{"follows the guard mode", "[guard]\nenabled = true\nmode = \"observe\"\n\n[guard.prompt]\nenforce_independent = false\n", "", false, false},
		{
			"the organization's guard mode decides", "[guard]\nenabled = true\nmode = \"observe\"\n",
			`{"schema":1,"state":"applied","pinned":{"guard.mode":"observe"}}`, false, true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, cfgPath := newSecretTestServer(t, tc.body)
			if tc.sidecar != "" {
				// The sidecar sits beside the database the config names.
				dir := filepath.Dir(cfgPath)
				body := "[observer]\ndb_path = '" + filepath.ToSlash(filepath.Join(dir, "observer.db")) + "'\n" + tc.body
				if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, config.GovernanceSidecarFilename), []byte(tc.sidecar), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/guard/summary", nil))
			if rr.Code != http.StatusOK {
				t.Fatalf("%d %s", rr.Code, rr.Body.String())
			}
			var v struct {
				PromptGuard *struct {
					Mode               string `json:"mode"`
					EnforceIndependent bool   `json:"enforce_independent"`
					SetByOrg           bool   `json:"set_by_org"`
				} `json:"prompt_guard"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil || v.PromptGuard == nil {
				t.Fatalf("prompt_guard missing: %v %s", err, rr.Body.String())
			}
			if v.PromptGuard.EnforceIndependent != tc.wantIndep || v.PromptGuard.SetByOrg != tc.wantOrg || v.PromptGuard.Mode == "" {
				t.Fatalf("%+v", v.PromptGuard)
			}
		})
	}
}
