// Package jobs is the queue abstraction, the inference worker and its
// executors for the hosted cloud-intelligence service (plan §6 CI-P3/CI-P4).
//
// The queue is Postgres-backed only: the analysis_jobs table with lease
// columns IS the queue, dequeued through the SECURITY DEFINER lease function,
// behind a narrow Queue interface (queue.go). The worker (worker.go) leases a
// job and re-runs the fail-closed revalidation gates before every attempt;
// LunaExecutor (executor.go) then makes one bounded, non-agentic provider
// call per attempt through the inference seam (Anthropic or Foundry, by the
// route's dialect) and settles the result and the reservation atomically.
// The pure per-call stages (prompt build, completion normalize/scrub/ground)
// live in luna.go, and the project-digest pass in digest.go, scheduled by
// digest_scheduler.go.
package jobs
