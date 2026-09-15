# sbci-cloud-edge-staging — the W6e authenticated Cloudflare hop

Extracted verbatim from `../README.md` (W6e section) so the operator can deploy
without copy-pasting out of prose. `src/index.js` is the Worker; `wrangler.toml`
pins the staging ACA origin. The shared secret is NEVER in this directory — it is
installed with `wrangler secret put SBCI_EDGE_SHARED_SECRET` from the Key Vault
value (see the runbook steps in `../README.md` §"Cloudflare authenticated proxy
hop" and the operator runbook artifact of 2026-09-03).

```bash
cd scripts/cloudintel/edge-worker
npx wrangler login
edge_value="$(cd /mnt/c && cmd.exe /c "az keyvault secret show --vault-name sbci-staging-kv35022 --name sbci-edge-shared-secret --query value -o tsv" | tr -d '\r\n')"
test "${#edge_value}" -eq 64
printf '%s' "$edge_value" | npx wrangler secret put SBCI_EDGE_SHARED_SECRET --name sbci-cloud-edge-staging
unset edge_value
npx wrangler deploy
```
