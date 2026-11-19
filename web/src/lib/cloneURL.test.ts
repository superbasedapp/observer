import { test } from "node:test";
import assert from "node:assert/strict";
import { carriesCredential, cloneURLProblem } from "./cloneURL.ts";

// The dialog's mirror of internal/workspace's clone URL rules (remote_test.go
// TestValidateRemoteURL and boxclone_test.go's credential rows), one row per
// case. The live-run report (2026-11-18): https://user@host/repo showed the
// daemon's raw error and left Start enabled.

const local = { noCredential: false };
const hosted = { noCredential: true };

const CASES: Array<[name: string, url: string, rules: { noCredential: boolean }, want: RegExp | null]> = [
  ["https accepted", "https://github.com/example/repo.git", local, null],
  ["ssh accepted", "ssh://git@github.com/example/repo.git", local, null],
  ["scp form accepted", "git@github.com:example/repo.git", local, null],
  ["scp form, no subdir", "git@github.com:repo.git", local, null],
  ["empty is asked for apart", "   ", local, null],
  ["ext transport", "ext::sh -c 'rm -rf /'", local, /space/],
  ["ext transport, no space", "ext::evil", local, /ext:: form/],
  ["fd helper", "fd::0", local, /name::address/],
  ["named helper", "testgit::x", local, /name::address/],
  ["hg helper", "hg::https://example.com/r", local, /name::address/],
  ["file scheme", "file:///etc/passwd", local, /file:\/\//],
  ["leading dash", "-evilhost/repo.git", local, /dash/],
  ["upload-pack", "https://github.com/x/--upload-pack=evil.git", local, /--upload-pack/],
  ["receive-pack", "https://github.com/x/--receive-pack=evil.git", local, /--upload-pack or --receive-pack/],
  ["NUL byte", "https://github.com/x\u0000y.git", local, /invisible character/],
  ["inner space", "https://github.com/x y.git", local, /space/],
  ["newline", "https://github.com/x\ny.git", local, /invisible character/],
  ["git scheme", "git://github.com/example/repo.git", local, /https:\/\/, ssh:\/\/ or user@host:path/],
  ["http scheme", "http://github.com/example/repo.git", local, /https:\/\/, ssh:\/\/ or user@host:path/],
  ["windows drive", "C:\\repo", local, /https:\/\/, ssh:\/\//],
  ["bare token", "repo.git", local, /https:\/\/, ssh:\/\//],
  ["no host", "https:///repo.git", local, /no host/],
  // A local row clones with this machine's ambient auth: a user name is allowed.
  ["local row, user name kept", "https://user@github.com/acme/app.git", local, null],
  // A hosted row's clone refuses any credential in the URL.
  ["hosted, user name", "https://user@github.com/acme/app.git", hosted, /user name, password or token/],
  ["hosted, user and token", "https://x:ghp_abc@github.com/acme/app.git", hosted, /user name, password or token/],
  ["hosted, query", "https://github.com/acme/app.git?access_token=1", hosted, /user name, password or token/],
  ["hosted, fragment", "https://github.com/acme/app.git#t", hosted, /user name, password or token/],
  ["hosted, ssh password", "ssh://git:pw@github.com/acme/app.git", hosted, /user name, password or token/],
  ["hosted, ssh user only", "ssh://git@github.com/acme/app.git", hosted, null],
  ["hosted, scp user", "git@github.com:acme/app.git", hosted, null],
  ["hosted, public https", "https://github.com/acme/app.git", hosted, null],
];

for (const [name, url, rules, want] of CASES) {
  test(`cloneURLProblem: ${name}`, () => {
    const got = cloneURLProblem(url, rules);
    if (want === null) assert.equal(got, null);
    else {
      assert.ok(got, `expected a problem for ${JSON.stringify(url)}`);
      assert.match(got, want);
      assert.doesNotMatch(got, /workspace\.|Validate|terminal_sandbox|%q/, "plain words, no internal text");
    }
  });
}

test("carriesCredential: the scp form's user names no secret", () => {
  assert.equal(carriesCredential("git@github.com:acme/app.git"), false);
  assert.equal(carriesCredential("https://u@h/r"), true);
  assert.equal(carriesCredential("ssh://u@h/r"), false);
  assert.equal(carriesCredential("ssh://u:p@h/r"), true);
});
