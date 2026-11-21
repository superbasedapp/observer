# Paddle fixtures

Response bodies for `paddleapi`'s tests, written to Paddle Billing's
documented shapes (API version 1: the `data` / `meta.request_id` envelope,
the `error` object with `type`, `code`, `detail`, `documentation_url`;
subscription `billing_cycle`, `current_billing_period`, `items[].price.id`,
`items[].quantity`; the customer portal session `customer_id` and `urls`:
`portal_session.json`, wave 17; the cancel answer and a refused cancel:
`cancel_subscription.json`, `error_cancel_refused.json`, FR-1, whose error
code is illustrative: the deletion's seam reads the subscription again
rather than trusting any one code).
Every id is fictional and no file holds a key, a customer address or a live
response. They are NOT recordings of a live sandbox call: this lane had no
network and no sandbox key (operator item C9). When the sandbox key exists,
replace each file with a recorded sandbox response (redacted the same way)
and keep the tests.
