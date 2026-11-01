package secgithooks

import "github.com/marmutapp/superbased-observer/internal/secrules"

// The pre-push hook's history-only hold (lane sec-gate4 milestone 1d,
// decision log P-039): a secret committed and then removed from the files
// is still in the commit, and the daemon holds that commit until every
// remote has it. The hooks treat the hold as the agent's commit gate does
// (S-791 and S-792): pre-commit is never refused because of it (a new
// commit adds nothing to what a push sends of the old one), pre-push is
// when the push sends a held commit to a remote that does not have it yet.

// HeldCommit is one held commit the signed posture lists: its full id and
// the remotes whose remote-tracking refs already have it.
type HeldCommit struct {
	Commit  string
	Remotes []string
}

// Sends reports whether the push being checked sends commit (the commit is
// in one of the pushed ranges); known is false when git could not answer.
type Sends func(commit string) (sends, known bool)

// PrepushHold returns the first held commit the push sends to remote (the
// name git passes the hook; a URL or "" is a remote no held commit is on),
// and whether the push is refused for it. A held commit the remote already
// has is skipped; one git cannot place in the pushed ranges does not
// refuse (the hook fails open). overflow is the posture's capped held
// list (more held commits than it names, lane sec-gate4 audit finding 8):
// the commits past the cap cannot be proven to be on any remote, so a push
// no listed commit refuses is refused for them, with commit "".
func PrepushHold(remote string, held []HeldCommit, overflow bool, sends Sends) (string, bool) {
	if sends == nil {
		return "", false
	}
	for _, h := range held {
		if onRemote(h, remote) {
			continue
		}
		if s, known := sends(h.Commit); known && s {
			return h.Commit, true
		}
	}
	if overflow {
		return "", true
	}
	return "", false
}

func onRemote(h HeldCommit, remote string) bool {
	if remote == "" {
		return false
	}
	for _, r := range h.Remotes {
		if r == remote {
			return true
		}
	}
	return false
}

// HeldRefusalLine is the one line the pre-push check prints for a held
// commit (its first 12 characters) and the remote; commit "" is the capped
// list's refusal. Dropping the commit (amend, rebase or reset) does not
// release the hold while the reflog still reaches it, so the line gives
// the agent gate's release step (secrules.PushReleaseStep, the one owner
// of S-792's wording; SEC-GATE5 follow-up), never "retry".
func HeldRefusalLine(commit, remote string) string {
	if len(commit) > 12 {
		commit = commit[:12]
	}
	where := "this remote"
	if remote != "" {
		where = "remote " + remote
	}
	if commit == "" {
		return "observer: push refused: more unpushed commits add a secret than the project's security state lists, so this push may send one that is not on " + where +
			" yet. Dropping the secrets from those commits (amend, rebase or reset) releases this only once the reflog no longer reaches them: after dropping them, run " + secrules.PushReleaseStep + ", or review the findings on Code security > Findings; to skip this check once, use --no-verify."
	}
	return "observer: push refused: commit " + commit + " adds a secret that is not on " + where +
		" yet (it was removed from the files, not from the commit). Dropping it from the commit (amend, rebase or reset) releases this only once the reflog no longer reaches it: after dropping it, run " + secrules.PushReleaseStep + ", or rotate the secret; to skip this check once, use --no-verify."
}
