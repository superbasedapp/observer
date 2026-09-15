# Paddle golden webhook fixtures (A10, updated 2026-09-12 with real sandbox captures)

## Provenance (2026-09-12)

A Paddle sandbox account and staging webhook destination are now live
(`https://cloud.superbased.app/portal/webhooks/paddle`, notification setting
`ntfset_01m28zm6mx586yvxzjq3ktps0m`). Most fixtures below are REAL deliveries
captured from that destination on 2026-09-12, pulled via `GET /notifications`
(real checkout deliveries) and `GET /simulations/{id}/events` (Paddle
simulator deliveries), not reconstructed from Paddle's public docs. Every
delivery listed here got HTTP 200 from staging.

### Real checkout deliveries (origin=event)

One real sandbox checkout (subscribe -> trial start -> price change ->
cancel) produced these. Each file is the exact body Paddle delivered,
copied verbatim (no trimming, no scrubbing) - `event_id`/`event_type`/
`occurred_at`/`notification_id`/`data` all present and unmodified. The
sandbox customer email on these (`sandbox-test@superbased.app`) and the
sandbox test card (Visa `...4242`) are test fixtures, not real PII.

- `subscription.created.json` - notification `ntf_01m290dhyaxtpbagqs68ktbxff`,
  event `evt_01m290dhjnypyztxqwwy77624p`. `data.status = "trialing"`.
- `subscription.trialing.json` - notification `ntf_01m290dhy4ejhd9yec0x7835yt`,
  event `evt_01m290dhjnmrhk28dhae0c904c`. Same checkout, delivered alongside
  `subscription.created` (Paddle sends both on a trial-priced subscribe).
- `transaction.completed.json` - notification `ntf_01m290djdm0dwskdezhb8nj11d`,
  event `evt_01m290dhwkcyw58rj5dq5fg82f`. The $0 trial-start transaction; see
  "Live-observed facts" below.
- `subscription.updated.json` - notification `ntf_01m290te1ff2n4vm4z177w1bk1`,
  event `evt_01m290tdmhc7tah8n36tecrsp7`. `data.status = "canceled"` - this
  particular delivery is the cancel-with-updated half of a same-second
  cancel pair, not a price change, so it classifies as `cancel`, not
  `activate`.
- `subscription.canceled.json` - notification `ntf_01m290te1z8z6nk2dpp260d09j`,
  event `evt_01m290tdmhpt6zhh427y7x02p9`. `effective_from: immediately`
  (not carried on `store.PaddleEvent` today; the classifier acts on
  `event_type` + `data.status` alone).
- `transaction.created.json` - notification `ntf_01m29064z2sva48xjw9j6gp2px`,
  event `evt_01m29064p4wga15yb49h2q6xe8`. Precedes `.ready`/`.paid`/`.completed`
  for the same transaction id; explicit-ignore row.
- `transaction.ready.json` - notification `ntf_01m290c8ma8pgp8hm2ez4skhcj`,
  event `evt_01m290c8b7yjvg9zf7pc7fwezd`. Explicit-ignore row.
- `transaction.paid.json` - notification `ntf_01m290dhh65d5phv15hkgpytqz`,
  event `evt_01m290dh6trn1sjh0d2bjqxcec`. Explicit-ignore row.
- `transaction.updated.json` - notification `ntf_01m290djazjf0fmfqk3t55r4k4`,
  event `evt_01m290dhwhk35t9pm951wavfxv`. There were three `transaction.updated`
  deliveries on this checkout; this is the THIRD one (`data.status =
  "completed"`, `data.subscription_id` populated) specifically because it is
  the one that carries a subscription id - the strongest shape for an
  ignore-row assertion (ignored even though it looks bindable).

### Simulator deliveries (origin=simulation)

Paddle's simulator replays its own canned example entities (a fictional
company "AeroEdit Pro" / customer "Michael McGovern" for the transaction
fixture, price ids that don't exist in our sandbox) and signs + delivers
them for real - our handler acknowledged all three with HTTP 200, each as
`outcome=unattributed` (their subscription/customer ids are Paddle's own
canned example ids, never bound to any of our accounts).

These three were captured via `GET /simulations/{id}/events`, which returns
only the bare entity (`data`'s contents), not the full webhook envelope -
unlike the `/notifications` listing above. So for these three fixtures the
`data` object is 100% verbatim from Paddle's simulator delivery, but the
envelope shell (`event_id`, `event_type`, `occurred_at`) is SYNTHESIZED
around it so `DecodePaddleWebhookEnvelope` (which requires non-empty
`event_id`/`event_type`) can parse the fixture. `event_id` is marked with an
obvious `evt_sim_` prefix (never a real Paddle-issued id) built from the
entity's own real id; `occurred_at` is the entity's own real `updated_at`.
No `notification_id` is stamped on these three: the three simulation
notification ids actually delivered during this run
(`ntfsim_01m290teh7994bctn7pam3mskf`, `ntfsim_01m290tf84fdzcbg4sf2hehg64`,
`ntfsim_01m290tfzdcz8ypnk4sz314xhn`, from `GET /simulations/.../events`) were
not preserved per-type by the capture, so no unverified type-to-id mapping
is asserted here.

- `subscription.past_due.json` - simulator body for `sub_01hv8x29kz0t586xy6zn1a62ny`,
  `data.status = "past_due"`. Synthesized `event_id`:
  `evt_sim_sub_01hv8x29kz0t586xy6zn1a62ny`.
- `transaction.payment_failed.json` - simulator body for
  `txn_01hv8wptq8987qeep44cyrewp9`, `data.status = "ready"`,
  `data.subscription_id = null` (a payment-failed transaction need not be
  tied to a subscription; our classifier doesn't require one either).
  Synthesized `event_id`: `evt_sim_txn_01hv8wptq8987qeep44cyrewp9`.
- `adjustment.created.refund_full_approved.json` - simulator body for
  `adj_01hvgf2s84dr6reszzg29zbvcm`, `data.action = "refund"`,
  `data.type = "partial"`, `data.status = "pending_approval"`. Synthesized
  `event_id`: `evt_sim_adj_01hvgf2s84dr6reszzg29zbvcm`.

  **Naming note:** the filename says "full_approved" but the real simulator
  delivery Paddle actually sent for `adjustment.created` is a PARTIAL,
  `pending_approval` refund, not a full/approved one - Paddle's simulator
  only offers this one canned adjustment example. Per the working rule for
  this update (use the real simulator body for this file whenever its
  `data.action` is `"refund"`, which it is), the file's CONTENT was replaced
  with the real body rather than left as the old documented full/approved
  example; the FILENAME was kept unchanged for continuity with the existing
  golden-test table and fixture history. Feeding this through
  `resolveAdjustmentAction("refund", "partial", "pending_approval")` yields
  `status_only` (not `revoke`) - a partial, still-pending refund changes
  nothing yet - and the golden test's expectation for this file was updated
  to match. The full/approved shape `resolveAdjustmentAction` treats as a
  revoke is still exercised, just by `adjustment.created.chargeback.json`
  and by `store.TestClassifyPaddleEventTable`'s hand-built adjustment cases,
  not by this file.

### Still documented examples (no real capture exists)

- `subscription.activated.json` - kept as Paddle's documented example
  (unchanged). Our price (`plus_beta`) carries a 7-day trial, so a purchase
  produces `subscription.created` + `subscription.trialing`, never
  `subscription.activated` - there is nothing to capture for this event on
  the current pricing model.
- `adjustment.created.chargeback.json` - kept as the reconstructed example
  (unchanged; see history below). No chargeback occurred against the
  sandbox account, so there is nothing to capture.

## Live-observed facts worth recording for future readers

- **Trial-start `transaction.completed` carries ZERO totals.** The captured
  `transaction.completed.json` (the transaction Paddle raises when a
  trial-priced subscription starts) has `details.totals.total = "0"` (and
  every other total field: `"0"`), because nothing is actually charged at
  trial start. `data.billing_period` on that transaction is the trial week
  itself (`starts_at`/`ends_at` matching the subscription's `trial_dates`),
  not a future billed period. `data.items[0].price.trial_period` is present
  (`{"interval":"day","frequency":7,...}`). The classifier still treats this
  as `activate, binds=true` (a non-empty `data.subscription_id` is all it
  requires) - this is a trial-start confirmation, not a payment amount
  check, and that's intentional: the subscription is what carries
  entitlement, not this specific transaction's total.
- **`management_urls` arrived `null` on every subscription delivery seen.**
  `subscription.created.json`, `subscription.trialing.json`,
  `subscription.updated.json`, and `subscription.canceled.json` from this
  real checkout all carry `data.management_urls: null` in Paddle's sandbox
  (not merely omitted - explicitly `null`). This is consistent with Paddle's
  documented statement that `subscription.updated` excludes
  `management_urls`, but our live captures show the sandbox omits it more
  broadly than that one documented exception. `paddleEventFromEnvelope`
  already handles this fine (an empty `ManagementURLs` struct decodes to two
  empty strings); see "What these fixtures do NOT cover" below for the one
  gap this leaves.

## History (pre-2026-09-12)

Before a Paddle account existed, every fixture here was reconstructed from
Paddle's own documented example webhook payloads at developer.paddle.com (or,
for `adjustment.created.chargeback.json`, hand-built following the same
documented schema with no worked example to start from - Paddle's docs page
showed no chargeback example at all). That generation is fully superseded by
the real captures above wherever a real capture exists; the docs-derived
versions are preserved only for `subscription.activated.json` and
`adjustment.created.chargeback.json`, per "Still documented examples" above.

## What these fixtures do NOT cover

- `management_urls` end-to-end through a POPULATED value: every live capture
  above has it `null` (see "Live-observed facts"), so no fixture here
  exercises `paddleEventFromEnvelope`'s `ManagementURLs` decode path with a
  real, non-empty URL pair. The parsing/validation logic itself (https +
  paddle.com/*.paddle.com acceptance) is covered directly by
  `store.TestPaddleManagementURLAcceptReject`, which feeds
  `PaddleEvent.ManagementUpdateURL` without needing a webhook-shaped fixture.
- `subscription.imported` and `transaction.billed|canceled` (also
  explicit-ignore rows) still have no fixture, real or documented; they're
  covered by `store.TestClassifyPaddleEventTable` instead, which exercises
  the classifier directly over hand-built `PaddleEvent` values.
- A full/approved refund and a chargeback, as REAL deliveries - both remain
  documented-example-only per "Still documented examples" above.

## The test

`api.TestPaddleGoldenFixturesClassify` (in `../paddle_test.go`) reads each
file here, decodes it through the REAL `api.DecodePaddleWebhookEnvelope` (the
exact function `handlePaddleWebhook` itself calls - no parallel decode
logic), and classifies the result through `store.ClassifyPaddleEvent`,
asserting the expected `(kind, binds)` pair per fixture.
`api.TestPaddleGoldenFixtureTransactionCompletedCarriesSubscriptionID` pins
that a real `transaction.completed` payload's `data.subscription_id` decodes
onto `PaddleEvent.SubscriptionID`, not `data.id`.
