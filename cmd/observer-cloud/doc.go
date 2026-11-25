// Command observer-cloud is the SuperBased hosted cloud-intelligence service
// (arc-2 CI-P3 foundation). It is a wholly separate binary from `observer`
// (the agent) and `observer-org` (the customer-self-hosted org server):
// different config, a different database (Postgres, not SQLite), and a
// different deployment (one box under docker compose: deploy/cloud-box/; the
// Azure Container Apps substrate is retired).
//
// Subcommands:
//
//	serve       run the /v1 API + portal-BFF HTTP server (the only public ingress)
//	worker      run the inference worker (lease → revalidate → provider call)
//	migrate     apply the Postgres migration lineage and report the schema version
//	grant-plan  assign an entitlement plan to an account (operator beta grant; runs
//	            and exits — there is deliberately no HTTP route, because no payment
//	            rail exists yet)
//	prove       run the compiled-in synthetic fixture catalog through the real
//	            provider pipeline (operator-only, fixture-only; runs and exits).
//	            It has its OWN credential (SBCI_PROVE_ANTHROPIC_API_KEY, or
//	            SBCI_PROVE_FOUNDRY_API_KEY for foundry) and never reads the
//	            worker's, so ordinary account admission stays credential-absent
//	            (see internal/cloudserver/prove)
//	route bind-anthropic
//	            bind the Claude Haiku 5.5 route to the Anthropic API: endpoint,
//	            provider resource identity, and a price snapshot copied from
//	            the pricing table (operator-only; runs and exits)
//	signer oidc serve|keygen|public-key|promote|retire
//	            the platform OIDC issuer's id_token signer (managed-SaaS M6.2;
//	            its own systemd unit and Linux user; signer.go)
//	signer document serve|keygen|public-key|raise-floor
//	            the document signer for entitlements, the availability envelope
//	            and host-API requests (managed-SaaS M6.3; worker VM, its own
//	            unit and user; signer_document.go); raise-floor raises the
//	            database's version floors past a copy of the signer's record
//	            after a restore (operator, admin DSN; W16-D6)
//	oidc register-client
//	            register the platform OIDC client of an org provisioned
//	            without one (CPSIGN-13 backfill; operator, admin DSN, dry run
//	            by default; W16-D7; oidcclient.go)
//	staff serve the staff console: its own process, listener (:8091), host
//	            (staff.superbased.app) and database login (managed-SaaS M6.8,
//	            rulings A2/A3; staffserve.go). serve mounts no staff route.
//	staff enrol|credentials|revoke-credential
//	            the operator's staff passkey management, the only way a staff
//	            credential is created or recovered (staff.go)
//
// Configuration is 12-factor (env):
//
//	SBCI_PG_DSN             Postgres DSN (required). Used directly by migrate,
//	                        grant-plan, and prove (which run as the admin sbci_app
//	                        role), and as the fallback for the two role-scoped
//	                        DSNs below.
//	SBCI_API_PG_DSN         Postgres DSN the `serve` process connects with, whose
//	                        login role is a member of sbci_api ONLY (E2 / W6rs
//	                        least-privilege split). UNSET ⇒ falls back to
//	                        SBCI_PG_DSN (the single-role dev / staging-window
//	                        posture, where one principal assumes either role).
//	SBCI_WORKER_PG_DSN      Postgres DSN the `worker` process connects with, whose
//	                        login role is a member of sbci_worker ONLY. UNSET ⇒
//	                        falls back to SBCI_PG_DSN.
//	SBCI_STAFF_PG_DSN       Postgres DSN of the staff login (sbci_staff_svc, the
//	                        only member of sbci_staff) for `staff serve` and the
//	                        staff operator verbs. serve REFUSES to start when it
//	                        is set. SBCI_STAFF_LISTEN / SBCI_STAFF_BASE_URL /
//	                        SBCI_STAFF_HOST / SBCI_STAFF_SESSION_TTL /
//	                        SBCI_STAFF_SESSION_IDLE_TTL /
//	                        SBCI_STAFF_EDGE_SHARED_SECRET(_FILE): see
//	                        staffserve.go.
//	SBCI_LISTEN            API listen address (serve; default :8090)
//	SBCI_METRICS_LISTEN     the optional Prometheus /metrics listener (serve and
//	                        worker; host:port, e.g. 0.0.0.0:9470 for cloud-api and
//	                        0.0.0.0:9471 for cloud-worker inside the container,
//	                        published on the monitoring address only). Empty (the
//	                        default) opens nothing; never the public listen
//	                        address; a malformed value refuses to start (metrics.go)
//	SBCI_EXTERNAL_BASE_URL  absolute externally-visible origin (scheme+host[:port],
//	                        no trailing slash/path) used to reconstruct the htu a
//	                        client's proof-of-possession proof was bound to (serve;
//	                        default derived from SBCI_LISTEN — dev/test only. A
//	                        Cloudflare-fronted production deployment MUST set this
//	                        explicitly; the server never trusts X-Forwarded-* for it)
//	SBCI_DEV_AUTH=1         use the dev-auth identity stub (else the WorkOS verifier
//	                        when WORKOS_CLIENT_ID is set, or a fail-closed placeholder)
//	SBCI_PORTAL_BASE_URL    absolute externally-visible origin the PORTAL is served
//	                        at, when /portal/* and /v1/* live on two different names
//	                        (R5). It anchors the WorkOS redirect_uri and the portal
//	                        cookie mode. UNSET ⇒ falls back to SBCI_EXTERNAL_BASE_URL,
//	                        which is the single-host staging posture (unchanged
//	                        behaviour). With the browser sign-in leg ACTIVE and both
//	                        canonical hosts configured, it is REQUIRED and validated
//	                        (https, host == SBCI_PORTAL_HOST, distinct from
//	                        SBCI_API_HOST) — the server refuses to start otherwise
//	SBCI_PORTAL_SECURE      1/0 to force the portal session-cookie Secure mode
//	                        (default: derived from SBCI_PORTAL_BASE_URL's scheme —
//	                        https ⇒ __Host-sbci Secure cookie, http ⇒ dev fallback)
//	SBCI_PORTAL_WORKOS=1    activate the portal's WorkOS browser sign-in leg
//	                        (/portal/auth/workos/*). DARK BY DEFAULT: unset, those
//	                        routes answer an honest 501 and browser sign-in stays
//	                        dev-auth-only until the R7 exposure gates are green.
//	                        Requires WORKOS_CLIENT_ID + WORKOS_API_KEY[_FILE]; set
//	                        without them, serve refuses to start.
//	WORKOS_CLIENT_ID        public AuthKit client id (also selects the production
//	                        access-token verifier)
//	WORKOS_API_KEY / WORKOS_API_KEY_FILE
//	                        WorkOS client secret (or a file holding it; setting
//	                        both is a startup error), used ONLY for the server-side
//	                        authorization-code exchange; never sent to a browser
//	SBCI_WORKOS_AUTHORIZE_URL / SBCI_WORKOS_TOKEN_URL
//	                        override the AuthKit endpoints (default: production)
//	WORKOS_WEBHOOK_SECRET / WORKOS_WEBHOOK_SECRET_FILE
//	                        shared secret (or a file holding it, never both) the
//	                        account-lifecycle webhook
//	                        (POST /portal/webhooks/workos) verifies its
//	                        `WorkOS-Signature` HMAC against. UNSET ⇒ that route
//	                        answers 501 and reads nothing (fail closed — an
//	                        unauthenticated route that verified nothing would be
//	                        an account-revocation lever for anyone who can reach
//	                        the origin)
//	SBCI_PORTAL_HOST        canonical public host that serves /portal/* (R5),
//	                        e.g. app.superbased.app. Unset ⇒ unenforced (the
//	                        single-host staging deployment)
//	SBCI_API_HOST           canonical public host that serves /v1/* (R5), e.g.
//	                        cloud.superbased.app. Unset ⇒ unenforced. A request
//	                        for either prefix on any other Host is answered 421
//	                        Misdirected Request; /healthz stays host-agnostic
//	SBCI_EDGE_SHARED_SECRET 64 hexadecimal characters (32 random bytes) shared
//	                        only with the Cloudflare Worker. Every non-loopback
//	                        deployment requires it: the API authenticates the
//	                        proxy hop before trusting the private
//	                        X-SBCI-Client-IP header (the Worker copies the
//	                        inbound Cloudflare visitor IP into it; the reserved
//	                        CF-Connecting-IP is never trusted because Cloudflare
//	                        may rewrite it on a cross-zone subrequest). Loopback
//	                        development may omit it.
//	SBCI_QUEUE_MODE         pg (only mode implemented this phase; azure is a later swap)
//	SBCI_WORKER_ID          worker identity (worker; default hostname-derived)
//	SBCI_INFERENCE_PROVIDER anthropic (default) | foundry. Exactly one provider
//	                        family is wired per process (cmd/observer-cloud/provider.go)
//	SBCI_ANTHROPIC_API_KEY / SBCI_ANTHROPIC_API_KEY_FILE
//	                        the Anthropic key (or a file holding it). UNSET ⇒
//	                        credential ABSENT ⇒ every job parks
//	                        provider_policy_unverified with no provider call
//	SBCI_ANTHROPIC_EFFORT   output_config.effort: low (default) | medium | high
//	SBCI_ANTHROPIC_PROMPT_CACHE=0
//	                        drop the system-prompt cache breakpoint
//	SBCI_FOUNDRY_API_KEY    the Azure AI Foundry key (foundry family only)
//	SBCI_PROVIDER_RETENTION_DISCLOSED_RESOURCE / _POLICY_VERSION / _BY
//	                        the disclosed attestation mode; the ONLY mode that
//	                        authorizes the anthropic family (resource =
//	                        anthropic:messages:<model>, see `route bind-anthropic`)
//	SBCI_EVIDENCE_KEY / SBCI_EVIDENCE_KEY_FILE
//	                        the shared evidence-blob AES-256-GCM key (64 hex chars)
//	SBCI_OIDC_ISSUER        the platform OIDC issuer switch (serve; M6.2). Unset ⇒
//	                        no /oauth2 route is mounted. Set, it must equal the
//	                        portal origin plus /oauth2 or serve refuses to start;
//	                        the signer unit reads the same value
//	SBCI_OIDC_SIGNER_SOCKET the OIDC signer's unix socket (serve and the signer;
//	                        default /run/observer-cloud-oidc/signer.sock)
//	SBCI_OIDC_VM_ID         the name serve registers this VM's signer key under
//	                        (oidc_signing_keys.vm_id; default the hostname)
//	SBCI_OIDC_SIGNER_ALLOW_UID / SBCI_OIDC_SIGNER_KEY
//	                        the signer unit's own settings (signer.go)
//	SBCI_TENANT_DOMAIN      the parent domain of tenant dashboards (superbased.app);
//	                        the me/orgs CORS allow-list; UNSET ⇒ same-origin only
//	SBCI_PERSONAL_PLANE     serving (default) | retired: retired answers 410
//	                        moved_to_org_plane on the old personal-plane routes
//	                        (D-IND-7; internal/cloudserver/api/retired.go); any
//	                        other value refuses to start
//	SBCI_TENANT_CONTEXT_KEY / SBCI_TENANT_CONTEXT_KEY_FILE
//	                        the tenant-context HMAC key (hex, at least 64 digits),
//	                        the same on every process; `migrate` installs it and
//	                        serve / worker refuse to start when the database does
//	                        not verify it. UNSET ⇒ a process-random key that only
//	                        a login allowed to install keys can use (dev)
//	SBCI_PADDLE_PAST_DUE_GRACE_DAYS
//	                        worker, with the host-API client on: how many days a
//	                        past_due org subscription still carries its plan
//	                        after it entered past_due (1-90; default 14, L-124,
//	                        W16-D5); then the org falls to its grant, launch
//	                        window or floor. hostapiworker.go
//	SBCI_WAITLIST_RETRY_FLOOR
//	                        worker, with the host-API client on: the least delay
//	                        before a waitlisted create is sent again, a Go
//	                        duration from 1m to 1h (default 15m, W16-D5)
package main
