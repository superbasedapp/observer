# GitHub REST fixtures (Phase 0, 2026-10-15)

Trimmed responses from unauthenticated, read-only calls against public
repositories (cli/cli: merge-commit workflow; vercel/next.js: squash
workflow). Only the fields the delivery code reads are kept; user objects
are reduced to the login. See docs/plans/commit-pr-merge-tracking-plan-2026-10-15.md
section 12.1 for what each one proves.

- pulls_list_cli.json: GET /repos/cli/cli/pulls?state=all (list has no mergeable fields)
- pull_open_unstable.json: GET /pulls/14678 (mergeable true, mergeable_state unstable)
- pull_draft_clean.json: GET /pulls/14679 (draft true but mergeable_state clean)
- pull_merged_mergecommit.json: GET /pulls/14706 (merged, mergeable null/unknown)
- pull_commits_merged.json: GET /pulls/14706/commits
- commit_merge_commit.json: the two-parent merge commit ("Merge pull request #14706 ...")
- commit_pulls_merged.json: GET /commits/{branch sha}/pulls for a merge-commit PR
- squash_merge_commit.json, squash_pull_commits.json, squash_commit_pulls.json: next.js #100206 (one parent, " (#100206)" suffix; branch commit still maps to the PR)
- check_runs_mixed.json: GET /commits/{head}/check-runs (success, failure, skipped)
- combined_status_empty.json: GET /commits/{head}/status (state pending, total_count 0)
- reviews_commented.json: GET /pulls/14678/reviews
- commit_pulls_unknown_sha_422.json: 422 body for a sha not in the repository
