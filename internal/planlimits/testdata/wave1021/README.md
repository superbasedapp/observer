# Plans & limits fixtures: 2026-10-21 capture wave (AP-134)

Every file here is SYNTHESIZED. None is a captured vendor response and none
holds a real credential: the tokens and keys are the literal strings
`fixture-...`, the ids are `*_fixture`, and the `attacker.example.com` values
exist only to prove a stored base URL is ignored.

The shapes were grounded on 2026-10-23 from each vendor's own installed client
(field names and types only, no response was ever fetched):

| File | Shape source |
| --- | --- |
| `autohand_me_pro.json`, `autohand_me_free.json` | autohand-cli 0.9.8 dist: `AuthClient.fetchEntitlement`, `parseAccountEntitlementLimits`, `parseAccountQuota` (GET `https://api.autohand.ai/v1/auth/me`) |
| `autohand_config.json` | autohand-cli 0.9.8: `auth: { token, user, expiresAt }` in `~/.autohand/config.json` (only `auth.token` / `auth.expiresAt` are read) |
| `kimchi_credits.json` | kimchi 1.17.0 binary: `parseCreditsPayload` (GET `<llm host>/v1/credits`) |
| `kimchi_budget.json` | kimchi 1.17.0 binary: `parseBudgetPayload` / `parseBudgetEntry` (GET `<llm host>/v1/budget`) |
| `kimchi_config.json` | kimchi 1.17.0 binary: `readApiKeyFromConfigFile` / `loadConfig` (`~/.config/kimchi/config.json`) |
| `stakpak_billing.json` | stakpak 0.3.88 binary strings + the vendor's public source: `BillingResponse` / `Feature` / `Product` (GET `https://apiv2.stakpak.dev/v2/<username>/billing`) |

The vendors' numbers in these files are invented. A live reply that differs
from these shapes is reported as "Vendor changed its API", never as a wrong
number.
