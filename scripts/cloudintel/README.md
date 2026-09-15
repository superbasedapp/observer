# Cloud Intelligence — Azure staging IaC

Contract of record: `docs/plans/cloud-intelligence-azure-substrate-contract-2026-08-30.md`
(binding — this directory implements it, not the other way around).

## What this provisions

`cloudintel-azure.sh` stands up the **STAGING** substrate for the hosted
Cloud Intelligence service (`cmd/observer-cloud`) in resource group
`superbased-cloudintel-staging-rg`:

- Container Apps environment + Log Analytics workspace
- `sbci-api` — external HTTPS ingress container app (the only public ingress
  in the estate), running `observer-cloud serve`; application routes are
  exposed through a Cloudflare Worker authenticated proxy hop, not as a
  direct public origin
- `sbci-worker` — no-ingress container app scaled 0-N on
  `analysis-jobs` queue depth, running `observer-cloud worker`
- Postgres Flexible Server (burstable, 7-day PITR, `sslmode=require`)
- Storage account: queues `analysis-jobs` + `analysis-jobs-dead`, blob
  container `evidence` (soft-delete disabled, ~24-48h lifecycle-management
  delete rule as a last-resort backstop behind the app's own 1h sweeper)
- Key Vault (evidence wrap key, Postgres credentials)
- Two user-assigned managed identities (`sbci-api`, `sbci-worker`) with the
  least-privilege role assignments from contract §2, including four custom
  data-action roles that SPLIT coarse built-ins:
  - `Cloudintel Canary Reader (staging)` (`canary-reader-role.json`) —
    read-only on exactly one Foundry resource (worker);
  - `Cloudintel KV Crypto Wrap (staging)` (`kv-crypto-wrap-role.json`) —
    `read` + `wrapKey` only (api), and `Cloudintel KV Crypto Unwrap
    (staging)` (`kv-crypto-unwrap-role.json`) — `read` + `unwrapKey` only
    (worker), replacing the bundled built-in **Key Vault Crypto User**;
  - `Cloudintel Evidence Blob Writer (staging)`
    (`blob-evidence-api-role.json`) — `read`/`write`/`delete` (api), and
    `Cloudintel Evidence Blob Reader-Deleter (staging)`
    (`blob-evidence-worker-role.json`) — `read`/`delete` (worker), replacing
    the bundled built-in **Storage Blob Data Contributor**.
  Azure DATA-action custom roles can lag RBAC propagation (~5 min) on first
  assignment — a fresh `up` may see `AuthorizationFailed` briefly before the
  new definitions settle.
- A non-production Azure AI Foundry (Cognitive Services, `AIServices` kind)
  account, with a `luna` Global Standard model deployment (left unprovisioned
  until real model identifiers are set — see below)

## Verbs

```
scripts/cloudintel/cloudintel-azure.sh plan                idempotent-safe, NO az calls: print resolved names/region/SKUs for SBCI_ENV
scripts/cloudintel/cloudintel-azure.sh up                   idempotent create-or-skip
scripts/cloudintel/cloudintel-azure.sh db-bootstrap         login roles (sbci_svc + api/worker split) + DSN rotate
scripts/cloudintel/cloudintel-azure.sh status               read-only show/list
scripts/cloudintel/cloudintel-azure.sh edge-check           dual-host public-vs-direct-origin/header-spoof probes
scripts/cloudintel/cloudintel-azure.sh patch-worker-scale   fix an ALREADY-PROVISIONED worker's degenerate KEDA rule (gap 4.4)
scripts/cloudintel/cloudintel-azure.sh down                 delete the RG (typed confirm)
```

**`SBCI_ENV` selects the estate** (added for the production wave, gap
4.1/4.5): `staging` (default — every behaviour above stays byte-identical to
before this env split) or `prod`. `prod` picks a separate resource group
(`superbased-cloudintel-prod-rg`), production-shaped names (no `-nonprod`/
`-staging` suffix — append your own globally-unique numeric suffix, same
convention as staging's `…35022`), a `GeneralPurpose` Postgres tier with
35-day geo-redundant PITR (vs staging's `Burstable` 7-day), a VNet with two
delegated subnets + a NAT Gateway locking down `sbci-worker`'s egress (staging
keeps the public-access-firewall posture), and an always-warm (`minReplicas
1`) `sbci-api` — that last one is now the default for BOTH envs (gap 4.8: a
cold-scaled public API 404s instead of cold-starting). Run `plan` first to see
every resolved name before touching Azure: `SBCI_ENV=prod bash
scripts/cloudintel/cloudintel-azure.sh plan`. See
`docs/cloud-intelligence-staging-launch-runbook.md` §14 for the full
production cut-over sequence and §15 for incident verbs (kill-switch,
schema-check, rollback). **Nothing under `SBCI_ENV=prod` has been applied
against live Azure — this is DRY_RUN-verified authored code, exactly the
posture the staging script itself started in per its own header.**

`patch-worker-scale` fixes an already-provisioned `sbci-worker`'s degenerate
KEDA `queue-depth` scale rule (gap 4.4 — a pg-mode worker doesn't scale on
Azure Storage Queue depth, so the rule's type/metadata/auth never resolved
against anything real, and that unresolved state is what has been blocking
turning the worker's Foundry/evidence keys into Key Vault secretrefs, per
§7/§11 of the launch runbook) via a YAML patch
(`deploy/cloudintel/worker-scale-patch.yaml`) that sets fixed 1/1 replicas and
removes the scale rule entirely. A FRESH `up` (this revision onward) creates
new workers this way from the start — `patch-worker-scale` is only for an
app an older revision of this script already created.

`db-bootstrap` is the one-time Postgres connecting-login step (see manual step
5 below): it generates an `sbci_svc` login password, stores it in Key Vault,
runs `CREATE ROLE sbci_svc LOGIN` + `GRANT sbci_app TO sbci_svc` (via local
`psql` if present, else `az postgres flexible-server execute` with the
`rdbms-connect` extension), then rotates the `sbci-pg-dsn` Key Vault secret to
the `sbci_svc` DSN. It honors the same `DRY_RUN`/`CLOUDINTEL_APPLY` gate as
`up`. Run it once after `up`, then roll a new revision of both apps.

**Least-privilege api/worker split (E2 / W6rs).** Migration `0015_role_split.sql`
splits the shared `sbci_app` into two NOLOGIN NOBYPASSRLS application roles
`sbci_api` + `sbci_worker` (plus the future W5 read role `sbci_aggregator`), each
with per-table least-privilege grants, and grants both to `sbci_svc` so the
single-principal deployment keeps working. `db-bootstrap` also provisions the
two dedicated LOGIN principals for the real separation: `sbci_api_svc` (member of
`sbci_api` only) and `sbci_worker_svc` (member of `sbci_worker` only), storing
their DSNs in the Key Vault secrets `sbci-api-pg-dsn` and `sbci-worker-pg-dsn`.
The ACA api container reads `SBCI_API_PG_DSN` from `sbci-api-pg-dsn`; the worker
reads `SBCI_WORKER_PG_DSN` from `sbci-worker-pg-dsn`. Both env vars are OPTIONAL —
the `observer-cloud serve`/`worker` processes fall back to `SBCI_PG_DSN`
(`sbci_svc`) when unset — so wiring them is the final, non-blocking step;
`db-bootstrap` prints the exact `az containerapp` commands.

## DRY_RUN default / CLOUDINTEL_APPLY master switch

`DRY_RUN` defaults to `1`. In that mode every az invocation — state-changing
or read-only — is printed (`az ...`) and never executed; `up` and `status`
are both safe to run with zero environment set.

Real execution requires `CLOUDINTEL_APPLY=1` explicitly. Setting `DRY_RUN=0`
by itself does **not** enable execution — `CLOUDINTEL_APPLY=1` is the master
switch, and an explicit `DRY_RUN=1` in the environment always wins over it
(belt and suspenders). `down` additionally requires typing the exact
resource-group name at an interactive prompt; the script never passes
`-y`/`--yes` at the top level on its own initiative.

`edge-check` follows the same gate. With the default dry-run it prints the
six probes without contacting Azure or the public endpoint. With
`CLOUDINTEL_APPLY=1` it performs read-only `az` lookups and unauthenticated
HTTP probes, without changing Azure or Cloudflare configuration: both public
Worker routes must be 2xx, while both raw ACA application routes and both
raw-origin/header-spoof probes must be non-2xx. The public HTTP probes are not
database-read-only: `/v1/auth/nonce` inserts one short-lived nonce, and every
public probe consumes the shared per-IP rate-limit counter. Run the check once
per verification window and allow for that bounded test traffic.

On an existing `sbci-api`, `up` reads the current Key Vault secret reference,
edge environment value, canonical-host environment values, and HTTPS ingress
posture before applying anything. Re-running `up` with those values already in
place therefore does not issue needless Container Apps updates or revisions;
dry-run still prints the planned checks because it deliberately performs no
Azure reads.

## W6e origin boundary: Cloudflare authenticated proxy hop

The ACA consumption ingress is still an **external** HTTPS ingress because it
needs to receive the Cloudflare Worker subrequest. That means its generated
`*.azurecontainerapps.io` name is transport-reachable on the Internet. It is
not a supported public origin: every application route (`/v1/*` and
`/portal/*`) must reject a request that does not carry the authenticated edge
header. The only deliberate exception is `/healthz`, a content-free liveness
endpoint that ACA may need to reach from its own infrastructure probes. A
direct `/healthz` 200 is not evidence that the Cloudflare path is configured.

The request path is:

```
browser/node ──HTTPS──> Cloudflare Worker
                         ├─ cloud.superbased.app (device API)
                         └─ app.superbased.app (portal)
                              │ validates the incoming public hostname
                              │ strips client edge/forwarding headers
                              │ adds X-SBCI-Edge-Auth from Worker secret
                              │ adds authenticated X-SBCI-Edge-Host
                              │ copies CF-Connecting-IP to X-SBCI-Client-IP
                              ▼
                       ACA sbci-api origin FQDN ──> observer-cloud API
```

The exact contract is intentionally small and shared by the script, API, and
Worker:

| Location | Name | Meaning |
|---|---|---|
| Azure Key Vault | `sbci-edge-shared-secret` | 32 random bytes rendered as 64 hex characters; generated once by `up` and reused on later runs |
| ACA secret alias | `edge-shared-secret` | Key Vault-backed secret reference on `sbci-api` |
| API container env | `SBCI_EDGE_SHARED_SECRET` | Secretref value; the API verifies it in constant time before using any forwarded client IP |
| Worker request header | `X-SBCI-Edge-Auth` | Set only by the Worker; client-supplied copies are deleted |
| Worker request header | `X-SBCI-Edge-Host` | Set only by the Worker from the validated `cloud.superbased.app` or `app.superbased.app` hostname; client-supplied copies are deleted |
| Worker request header | `X-SBCI-Client-IP` | Private copy of the inbound Cloudflare client IP; client-supplied copies are deleted and the API uses it only after edge authentication |
| Worker inbound header | `CF-Connecting-IP` | Read once at the Cloudflare edge; it is reserved and may be rewritten on the cross-zone ACA subrequest, so it is not the API's identity source |
| Worker secret | `SBCI_EDGE_SHARED_SECRET` | Same value as the Key Vault secret; install with `wrangler secret put`, never in source or `[vars]` |
| Worker variable | `SBCI_ORIGIN_BASE_URL` | `https://<sbci-api ingress FQDN>`; fixed operator configuration, not user input |

The API must treat the direct ACA peer address as an ACA/Envoy infrastructure
address, not as the end-user address. After the edge secret passes, it must
require exactly one syntactically valid `X-SBCI-Client-IP` address and use that
private copy as the rate-limit identity. Cloudflare's `CF-Connecting-IP` is a
reserved header: for a Worker subrequest to an origin outside the Worker zone
(the ACA FQDN here), the runtime may replace it with a Worker/Cloudflare
egress address. The API must therefore ignore the outbound `CF-Connecting-IP`
value entirely. Likewise, `X-SBCI-Edge-Host` is what lets the
canonical-host fence recover the original public name after the Worker fetches
the ACA FQDN. `X-Forwarded-Host`, `X-Forwarded-For`, `X-Real-IP`, and similar
headers are not authority. The Worker strips them (including any
client-supplied `X-SBCI-Client-IP` and `X-SBCI-Edge-Host`) before the subrequest
and sets the private headers itself. This is why an attacker who sends forged
client-IP or host headers directly to the ACA FQDN still fails: the headers
alone are never the authenticated hop.

### Install the Worker (operator-owned Cloudflare account)

The az-only script provisions the Azure-side secret and secretref, but never
calls the Cloudflare API and never asks an agent to enter credentials. After
`up` has completed, obtain the origin FQDN from `status` and create a Worker
project in the Cloudflare account that owns `superbased.app`. The following is
the complete Worker logic; keep it in the operator's private Worker project,
not in this repository or a public Worker bundle:

```js
const EDGE_AUTH_HEADER = "X-SBCI-Edge-Auth";
const EDGE_HOST_HEADER = "X-SBCI-Edge-Host";
const EDGE_CLIENT_IP_HEADER = "X-SBCI-Client-IP";

const STRIPPED_HEADERS = [
  "x-sbci-edge-auth",
  "x-sbci-edge-host",
  "x-sbci-client-ip",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-real-ip",
];

// Fallback accepted public hosts when SBCI_PUBLIC_HOSTS is unset (the shape
// every deployment before the 2026-09-14 hostname move ran with).
const DEFAULT_PUBLIC_HOSTS = [
  "cloud.superbased.app",
  "app.superbased.app",
];

// publicHostsFor returns the set of public hostnames this Worker will proxy.
// SBCI_PUBLIC_HOSTS (a comma-separated [vars] entry, per Wrangler environment)
// overrides the default so staging and production can each fence exactly the
// hostname their Cloudflare route carries; the Worker route is the first
// filter, this set is the second. Blank entries are ignored.
export function publicHostsFor(env) {
  const raw = typeof env.SBCI_PUBLIC_HOSTS === "string" ? env.SBCI_PUBLIC_HOSTS : "";
  const hosts = raw
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter((h) => h.length > 0);
  return new Set(hosts.length > 0 ? hosts : DEFAULT_PUBLIC_HOSTS);
}

export default {
  async fetch(request, env) {
    if (!env.SBCI_EDGE_SHARED_SECRET || !env.SBCI_ORIGIN_BASE_URL) {
      return new Response("edge proxy is not configured", { status: 503 });
    }

    const incoming = new URL(request.url);
    const publicHost = incoming.hostname.toLowerCase();
    if (!publicHostsFor(env).has(publicHost)) {
      return new Response("unknown public edge host", { status: 421 });
    }

    let origin;
    try {
      origin = new URL(env.SBCI_ORIGIN_BASE_URL);
    } catch (_) {
      return new Response("edge proxy origin is invalid", { status: 503 });
    }
    if (origin.protocol !== "https:") {
      return new Response("edge proxy origin must use HTTPS", { status: 503 });
    }

    // Cloudflare supplies this header at the edge. Reject a missing or
    // comma-separated value so the API receives one candidate address only.
    const clientIP = request.headers.get("CF-Connecting-IP");
    if (!clientIP || clientIP.includes(",")) {
      return new Response("missing or ambiguous client address", { status: 400 });
    }

    origin.pathname = incoming.pathname;
    origin.search = incoming.search;

    const headers = new Headers(request.headers);
    for (const name of STRIPPED_HEADERS) headers.delete(name);
    headers.delete("cf-connecting-ip");
    // CF-Connecting-IP is reserved and can be rewritten by the runtime when
    // this fetch crosses from the superbased.app zone to Azure. Preserve the
    // value in a private header instead; the API accepts it only after the
    // authenticated edge proof succeeds.
    headers.set(EDGE_CLIENT_IP_HEADER, clientIP.trim());
    headers.set(EDGE_AUTH_HEADER, env.SBCI_EDGE_SHARED_SECRET);
    // The ACA fetch necessarily changes Host to the fixed origin FQDN. Pass
    // the validated public hostname in a separate private header so the API's
    // canonical-host fence can still distinguish its /v1 and /portal names.
    headers.set(EDGE_HOST_HEADER, publicHost);

    const init = {
      method: request.method,
      headers,
      redirect: "manual",
    };
    if (request.method !== "GET" && request.method !== "HEAD") {
      init.body = request.body;
    }
    // The URL host is the fixed ACA origin host. Do not derive it from the
    // incoming URL; otherwise this becomes an SSRF-capable open proxy.
    return fetch(new Request(origin, init));
  },
};
```

The Worker project should keep the origin and route in ordinary, reviewable
configuration while keeping the shared value out of it. Replace the example
origin with the FQDN printed by `status`:

```toml
name = "sbci-cloud-edge-staging"
main = "src/index.js"
compatibility_date = "2026-09-02"

routes = [
  { pattern = "cloud.superbased.app/*", zone_name = "superbased.app" },
  { pattern = "app.superbased.app/*", zone_name = "superbased.app" },
]

[vars]
SBCI_ORIGIN_BASE_URL = "https://sbci-api.<generated-region>.azurecontainerapps.io"
```

Set `SBCI_ORIGIN_BASE_URL` as a non-secret Worker variable to the exact ACA
origin returned by `status` (for example,
`https://sbci-api.<generated-region>.azurecontainerapps.io`). Set the secret
without putting its value in shell history or a command argument. An operator
can use a private shell like this; it reads the Key Vault value into memory,
passes it over standard input to Wrangler, and removes the variable afterwards:

```bash
KV_NAME=sbci-staging-kv35022
WORKER_NAME=sbci-cloud-edge-staging
edge_value="$(az keyvault secret show --vault-name "$KV_NAME" \
  --name sbci-edge-shared-secret --query value -o tsv | tr -d '\r\n')"
test "${#edge_value}" -eq 64
printf '%s' "$edge_value" | npx wrangler secret put SBCI_EDGE_SHARED_SECRET --name "$WORKER_NAME"
unset edge_value
npx wrangler deploy --name "$WORKER_NAME"
```

If the local Wrangler version does not accept standard input, run the same
`wrangler secret put` command interactively and paste the value retrieved from
Key Vault; never put the value in `wrangler.toml`, JavaScript, a CI log, or a
command-line argument. Deploy the Worker with routes/custom domains covering
both `cloud.superbased.app/*` and `app.superbased.app/*`. Both the `cloud` and
`app` DNS records must be **proxied** (orange cloud), not DNS-only. A DNS-only
CNAME sends traffic directly to ACA and is exactly the bypass this lane closes.
If the ACA managed custom certificate is still being validated, temporarily use
DNS-only only for that validation, then switch both records to proxied mode
before any authenticated/browser exposure. The Worker origin fetch uses the
ACA-generated FQDN, so the public hostnames' certificates do not need to be
presented by the ACA origin.

Keep the Worker route narrower than any broad Pages route in the zone, and
confirm that the Worker—not a plain CNAME, Pages project, or redirect—is the
handler for both public hostnames. Do not point either Worker route back at its
own public hostname; that creates a loop. Do not use a quick tunnel or a
`workers.dev` URL as the production public origin.

### Boundary verification

Run the boundary check only after both Worker routes and the secret are
installed. It is read-only with respect to Azure/Cloudflare configuration, but
its public HTTP requests intentionally exercise bounded API state as described
above:

```bash
CLOUDINTEL_APPLY=1 scripts/cloudintel/cloudintel-azure.sh edge-check
```

It resolves the ACA FQDN and checks six cases:

1. `https://cloud.superbased.app/v1/auth/nonce` is 2xx through the Worker.
2. `https://app.superbased.app/portal/api/auth-config` is 2xx through the Worker.
3. `https://<ACA-FQDN>/v1/auth/nonce` without the secret is non-2xx.
4. `https://<ACA-FQDN>/portal/api/auth-config` without the secret is non-2xx.
5. The raw API request with forged `CF-Connecting-IP` and `X-SBCI-Edge-Host`
   headers is non-2xx.
6. The raw portal request with forged `CF-Connecting-IP` and
   `X-SBCI-Edge-Host` headers is non-2xx.

Do not add the secret to any curl probe. If either public case is not 2xx, the
corresponding Worker route, Worker secret, ACA secretref, or new ACA revision
is incomplete. If any raw-origin case is 2xx, stop: the R7 exposure gate is not
green.
Also inspect the response from the public route to ensure the API did not
receive a comma-separated or unexpected `CF-Connecting-IP`; the API's own
adversarial tests cover malformed, duplicate, IPv4, IPv6, and spoofed values,
and the Worker must be the only component allowed to set the authenticated
original-host header.

### Secret rotation

`up` is deliberately non-rotating: if `sbci-edge-shared-secret` exists, it
reuses it. Rotate only during a short maintenance window because the current
single-secret verifier has no dual-key grace period. The order below keeps the
failure mode fail-closed and avoids accidentally leaving the old secret in a
new revision:

1. Generate a new 32-byte value locally and create a new Key Vault version.
   Keep it out of history and logs:

   ```bash
   new_edge_secret_file="$(mktemp)"
   openssl rand -hex 32 | tr -d '\r\n' >"$new_edge_secret_file"
   az keyvault secret set --vault-name "$KV_NAME" \
     --name sbci-edge-shared-secret --file "$new_edge_secret_file" >/dev/null
   rm -f "$new_edge_secret_file"
   ```

2. Roll a fresh `sbci-api` revision so the unversioned Key Vault reference
   resolves the new version. Use a unique suffix; setting the same env value
   without a suffix can be a no-op and may not refresh the secret:

   ```bash
   az containerapp update -g "$RG" -n sbci-api \
     --revision-suffix "edge-$(date -u +%Y%m%d%H%M%S)" \
     --set-env-vars SBCI_EDGE_SHARED_SECRET=secretref:edge-shared-secret
   ```

3. Wait for the new revision to be healthy. The public route will return
   non-2xx until the Worker is updated; that short interruption is intentional
   rather than accepting either old or new secret.
4. Read the new Key Vault value in a private shell and run `wrangler secret
   put SBCI_EDGE_SHARED_SECRET --name sbci-cloud-edge-staging`, then deploy
   the Worker. Do not put the value in a Worker variable.
5. Run `edge-check`, inspect the ACA revision list, and deactivate the old
   revision only after the new one is healthy. If a secret is suspected to be
   exposed, perform this rotation immediately and treat the old value as
   compromised.

If zero-downtime rotation becomes a requirement, add an explicitly designed
dual-key verifier with an expiry window in the API first. Do not improvise a
second header or accept both values indefinitely. The Worker secret and the
API Key Vault version must always be changed as one operational change.

### Why this is not an ACA IP allow-list

An ACA external ingress request reaches the application through Azure's
managed ingress/Envoy path; `RemoteAddr` is not a durable promise that it will
be a Cloudflare egress address. Cloudflare's published IPv4/IPv6 ranges also
change and are not a substitute for authenticating the hop. An ACA IP rule
based on today's range list can either lock out legitimate edge traffic after
rotation or provide a false sense of origin exclusivity. The shared secret is
the authenticated boundary here, while `CF-Connecting-IP` is only an
identity/rate-limit input after that boundary succeeds.

For a future packet-level guarantee, move the ACA app to an internal ingress
and place a supported Cloudflare Tunnel connector in front of it, with its
own documented availability and secret-rotation design. That is a different
topology and is intentionally not claimed or provisioned by this script.

**First real apply: 2026-08-31 (eastus2).** The script was exercised end-to-end
against live Azure and the staging estate is up and serving. The **full
as-executed runbook** — every step actually taken (image build, region finding,
the two access grants, the DB role + DSN double-quote trap, custom domain, env
vars, WorkOS dashboard config, log diagnostics, teardown) — is
`docs/cloud-intelligence-staging-launch-runbook.md`. Read it before the next
apply or a re-provision. Findings folded in here:

- **Region:** `eastus` is capacity-restricted for Postgres Flexible Server on
  this subscription ("The location is restricted for provisioning of flexible
  servers") — the estate was applied in **`eastus2`** (`LOCATION=eastus2`).
- **Operator Key Vault access:** a fresh RBAC-authorization vault gives the
  subscription Owner no data-plane; `up` now runs `ensure_operator_kv_access`
  (grants the signed-in operator Key Vault Administrator + waits for RBAC
  propagation) before writing keys/secrets.
- **PG16 public schema:** the migration lineage now
  `GRANT CREATE ON SCHEMA public TO sbci_defs` (0003) — PG16 (which Azure
  Flexible Server runs) revoked public CREATE from PUBLIC.
- **Interop error detection:** `azexec_raw` treats an `az` `ERROR:` output line
  as failure, because the WSL→Windows `az` interop swallowed non-zero exits and
  the apply used to plow through failed steps reporting "done".
- **`db-bootstrap` limitation:** `az postgres flexible-server execute`
  (rdbms-connect) **hangs** under the WSL→Windows interop. Until that path is
  hardened, run the `sbci_svc` role SQL from a client that reaches Postgres
  directly (temporarily allow your IP on the PG firewall, then `psql` or a small
  pgx program: `CREATE ROLE sbci_svc LOGIN; ALTER ROLE sbci_svc PASSWORD '…';
  GRANT sbci_app TO sbci_svc;`), then rotate the `sbci-pg-dsn` KV secret to the
  `sbci_svc` DSN and roll both app revisions. Remove the temp firewall rule
  after.
- **⚠️ DSN double-quote trap:** store the `sbci-pg-dsn` secret as a **bare**
  `postgresql://…` string with **no surrounding quotes** and no trailing
  newline. A quoted value (`"postgresql://…"`) does not fail loudly — pgx can't
  parse the leading `"` as a URL scheme, silently falls back to a local unix
  socket as `user=<container-os-user>` with an empty dbname, and the app
  crash-loops (`dial unix /tmp/.s.PGSQL.5432: no such file or directory`) while
  Container Apps shows "Deployment Progress Deadline Exceeded" and curl gets HTTP
  000. Prefer `az keyvault secret set --file` to avoid all shell/interop
  quoting. `db-bootstrap` now **reads the secret back and refuses to proceed**
  unless it stores a bare `postgresql://sbci_svc:…` URL. Full write-up: the
  launch runbook §5b.

## Manual operator steps (not automated here)

1. **EA/MCA billing confirmation** — confirm the subscription used for this
   RG is on the intended Enterprise Agreement / Microsoft Customer Agreement
   before a real apply; the script does not check or set billing scope.
2. **Modified Abuse Monitoring filing** — required with Microsoft before any
   production Foundry resource can disable full content logging; not needed
   for the non-production resource this script creates, but must be filed
   before the production launch-gate item (contract §5/§1) is unblocked.
3. **Real Luna model identifiers** — set `LUNA_MODEL_NAME` and
   `LUNA_MODEL_VERSION` (and `LUNA_MODEL_FORMAT`/`LUNA_SKU` if needed) to the
   real GPT-5.6 Luna values before re-running `up`. Until then the script
   deliberately skips creating the `luna` deployment (it still creates the
   Foundry account) and prints the command it would have run.
4. **Foundry credential flip post-approval** — `up` never provisions a
   Foundry API key into Key Vault or the worker identity's env, by design
   (contract §1/§2 — "NO Foundry credential provisioned pre-approval"). Once
   the operator approval lands, add the key as a Key Vault secret and wire
   it into `sbci-worker`'s `--secrets`/`--env-vars` (mirroring the existing
   `pg-dsn` secretref pattern in `ensure_containerapp_worker`), then create a
   new container-app revision.
5. **Postgres connecting login role** — `az postgres flexible-server create`
   only provisions the server ADMIN login. The Postgres migration lineage
   (`internal/cloudserver/db/migrations/0001_roles.sql`) creates `sbci_app`
   (NOLOGIN — a privilege role the app assumes via `SET LOCAL ROLE
   sbci_app`) but no migration creates the LOGIN role that connects and is a
   member of it. `up` wires `SBCI_PG_DSN` to the admin login as a bring-up
   default. **This is now automated: run `db-bootstrap`** (see Verbs above),
   which creates `sbci_svc LOGIN`, `GRANT sbci_app TO sbci_svc`, stores the
   password in Key Vault, and rotates the `sbci-pg-dsn` secret to the
   `sbci_svc` DSN. Then roll a new container-app revision for both apps (the
   command it prints) so they connect as `sbci_svc`. This keeps the connecting
   role out of `BYPASSRLS`/ownership per contract §2, which the raw admin login
   does not.
6. **Public origins / `SBCI_PG_DSN` final-value confirmation** — `up` wires
   `SBCI_EXTERNAL_BASE_URL` to `$EXTERNAL_BASE_URL`
   (`https://cloud.superbased.app` by default), `SBCI_PORTAL_BASE_URL` to
   `https://app.superbased.app`, and `SBCI_PG_DSN` to a Key Vault secret
   reference. It also configures `SBCI_API_HOST=cloud.superbased.app` and
   `SBCI_PORTAL_HOST=app.superbased.app` for the canonical-host fence. Confirm
   both Cloudflare DNS/proxy routes are actually live through the Worker and
   point at the `sbci-api` Container Apps ingress FQDN (`observer-cloud` never
   trusts `X-Forwarded-*` for this, per its own doc comment) before treating
   proof-of-possession or portal flows as correct in staging. Plain DNS-only
   CNAMEs are not sufficient; complete the W6e steps below first.
6a. **Cloudflare authenticated proxy hop (W6e / E4)** — `up` creates
   `sbci-edge-shared-secret` in Key Vault and wires it to the API as
   `SBCI_EDGE_SHARED_SECRET`; it does not call Cloudflare or copy the secret
   into a Worker. Install the same value as the Worker secret
   `SBCI_EDGE_SHARED_SECRET`, configure the Worker to validate both public
   hostnames, add `X-SBCI-Edge-Auth` plus the authenticated
   `X-SBCI-Edge-Host`, and copy one inbound `CF-Connecting-IP` into the private
   `X-SBCI-Client-IP` header. Set the Worker origin to the raw ACA FQDN, make
   both `cloud` and `app` DNS records **proxied**, and run `edge-check`; stop
   exposure if any raw-origin application request is 2xx.
   The complete Worker code, secure copy procedure, and rotation runbook are in
   the W6e section above.
7. **Registry auth + image build** — the script assumes `sbci-api:latest` /
   `sbci-worker:latest` already exist in `$ACR` (default
   `sbdemoacr35022.azurecr.io`, the shared demo-estate registry) and deploys
   via managed-identity ACR pull (`--registry-identity`). It does not build
   or push images. BOTH tags are the **same** image, built from
   `Dockerfile.observer-cloud` at the repo root (mirrors
   `Dockerfile.observer-org`: pure-Go static binary on distroless/nonroot; the
   `webcloud/` portal is `go:embed`'d from its committed `webcloud/dist/`, so
   there is no npm stage). The container app selects the subcommand via
   `--args` (`sbci-api` -> `serve`, `sbci-worker` -> `worker`). Build + push
   once, tagging both:

   ```
   az acr build -r sbdemoacr35022 -f Dockerfile.observer-cloud \
     -t sbci-api:latest -t sbci-worker:latest .
   ```

   (`az acr build` uploads the context and builds+pushes server-side — no local
   Docker needed. Run it from a clean tree so only committed state is built.)
8. **Globally-unique names** — `$STORAGE_ACCOUNT`, `$KV_NAME`, `$PG_SERVER`,
   and `$FOUNDRY_NAME` all live in Azure-wide (or region-wide) uniqueness
   namespaces. Confirm/override the defaults before a real apply, the same
   way the existing demo estate appends a numeric suffix.

## Production (SBCI_ENV=prod)

This directory now scripts BOTH estates from the same file
(`cloudintel-azure.sh`, `SBCI_ENV=staging|prod` — see "Verbs" above), but they
remain operationally distinct: a separate resource group
(`superbased-cloudintel-prod-rg`, same subscription per the operator's
2026-09-12 ruling — Modified Abuse Monitoring does not require a separate
subscription), a VNet + NAT egress lockdown for `sbci-worker` (staging still
relies on app-layer egress allow-listing only, since Container Apps
Consumption tier has no per-app egress firewall — see `ensure_prod_network`),
35-day geo-redundant Postgres PITR instead of 7-day non-geo-redundant, and a
Foundry resource labeled `PRODUCTION` (cosmetic — see below) rather than
`NON-PRODUCTION`.

**What still makes a Foundry resource ACTUALLY production-safe is NOT
scriptable here**: the Modified Abuse Monitoring approval and a real (non-
operator-attested) `ContentLogging` attestation are a `cmd/observer-cloud`
runtime concern (`internal/cloudserver/attest`, gap 5.1), not an IaC concern.
This directory provisions the Foundry ACCOUNT; it cannot provision the
external Microsoft approval or flip the attestor away from
`OperatorAttestor`. See `docs/cloud-intelligence-staging-launch-runbook.md`
§14 for the ordered cut-over (RG apply → migrate → edge Worker → DNS →
WorkOS/Paddle live env → smoke → `SBCI_PORTAL_WORKOS=1`) and §15 for the
incident-response verbs (`observer-cloud kill-switch`, `schema-check`).

**As of this wave, `SBCI_ENV=prod` is authored and DRY_RUN-verified only — no
production resource has been created.** Every step in runbook §14 is marked
"operator go required".

### Production: in-VNet admin SQL (SBCI_PG_EXEC=acajob)

`sbci-prod-pg` is VNet-integrated with NO public endpoint (a creation-time
property of `ensure_postgres_server` under `SBCI_ENV=prod` - see
`ensure_prod_network`). `db-bootstrap`'s admin SQL (the `CREATE ROLE` /
`ALTER ROLE` / `GRANT` statements that mint `sbci_svc` and the split
`sbci_api_svc`/`sbci_worker_svc` login roles) normally runs from the
operator's own machine, over the public endpoint, via local `psql` or the
`az postgres flexible-server execute` fallback. Neither path can reach a
server with no public endpoint, so production needs a different transport
for exactly this one step.

`SBCI_PG_EXEC=acajob` (default: `local`, unchanged) routes every admin-SQL
call site through `pg_admin_sql_exec`, which runs the SQL inside a
Manual-trigger Container Apps Job (`${SBCI_ENV}-sbci-pgsql`) on the estate's
own `$CAE_NAME` - which sits on the VNet-integrated `cae-subnet`, so it can
reach the Postgres server on `pg-subnet` over the private VNet path that
production's own containers already use. The job:

- runs the public `docker.io/library/postgres:16-alpine` image (has `psql`;
  the Container Apps environment has NAT egress so the Docker Hub pull
  succeeds even though `sbci-worker`'s own image comes from the private ACR),
  `--cpu 0.25 --memory 0.5Gi`, `--replica-timeout 600
  --replica-retry-limit 0 --parallelism 1 --replica-completion-count 1`;
- receives the admin password and the SQL text as JOB SECRETS
  (`pgpassword` / `sql`), never as plain container args, mapped to
  `PGPASSWORD`/`SBCI_SQL` env vars via `secretref:`; the container command
  pipes `$SBCI_SQL` into `psql -f -` on stdin, because ACA's `--args`/
  `--command` cannot expand an env var itself;
- is created once per `db-bootstrap` run and then reused via
  `az containerapp job secret set` for the second (split-role) SQL
  statement, rather than being recreated;
- is started with `az containerapp job start`, polled via
  `az containerapp job execution list` until `Succeeded`/`Failed` (bounded,
  roughly 10 minutes), and on failure fetches the tail of
  `az containerapp job logs show` with every line containing the string
  `PASSWORD` filtered out before printing (falling back to printing the
  Log Analytics KQL query against `$LA_NAME` if `logs show` returns
  nothing on the installed az/containerapp extension version);
- is deleted at the end of `db-bootstrap` via a best-effort `EXIT` trap
  (`cleanup_pg_admin_job`) - a leftover job is harmless (Manual trigger, no
  schedule, no cost while idle) but is cleaned up anyway.

`SBCI_PG_EXEC=acajob` only changes how the admin-SQL statements themselves
run; the DSN readback checks that follow each rotation
(`sbci-pg-dsn`/`sbci-api-pg-dsn`/`sbci-worker-pg-dsn`) are plain
`az keyvault secret show` calls, not Postgres connections, so they are
unaffected either way. `up`, `status`, `edge-check`, `plan`,
`patch-worker-scale`, and `down` never touch Postgres directly and are also
unaffected. Staging keeps its public endpoint and never needs this mode -
`SBCI_PG_EXEC` defaults to `local` and staging's behavior is unchanged.

## Known gaps versus a literal reading of the contract

CI-P6 closed three of the originally-flagged gaps:

- **Postgres login role** — now automated by the `db-bootstrap` verb (manual
  step 5).
- **Key Vault Crypto role granularity** — the built-in Crypto User assignment
  is replaced by the `wrapKey`-only (api) / `unwrapKey`-only (worker) custom
  roles above.
- **Storage Blob role granularity** — the built-in Blob Data Contributor
  assignment is replaced by the `read/write/delete` (api) / `read/delete`
  (worker) custom roles above.

Still open (see the implementing agent's report): dead-letter queue access
inference, lifecycle-policy day-granularity, KEDA scale-rule syntax risk, and
the queue-mode contract-vs-code mismatch — the code's `SBCI_QUEUE_MODE` only
implements `pg` today; Azure Storage Queue consumption is provisioned as
infrastructure but not yet wired into `cmd/observer-cloud`. The apply-mode
path (incl. `db-bootstrap`'s psql / `az postgres flexible-server execute`
branches) remains authored-but-unexercised — treat the first real run as a
rehearsal.

The W6e edge-auth additions in this revision were made after that apply and
have **not** been exercised against live Azure or a live Cloudflare Worker.
Treat the next `up`/revision rollout and the Worker installation as an
operator-attended rehearsal; the repository makes no claim that the current
staging DNS is already Cloudflare-Worker-protected.

W6e's Azure-side boundary is now authored: `up` creates/reuses the Key Vault
edge secret, wires an ACA secret reference and both canonical public hosts,
enforces HTTPS-only ingress on an existing API app, and `edge-check` provides
the dual-public-route plus direct-origin/header-spoof probes. The Cloudflare
Worker, both proxied DNS routes, and the matching Worker secret remain
operator-owned and are **not** claimed live by this repository; the R7 gate
stays closed until `edge-check` passes against the deployed routes.
