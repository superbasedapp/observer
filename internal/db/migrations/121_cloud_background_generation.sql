-- Bind unattended consent to the exact policy generation that scheduled it.
-- These columns remain node-local on already-forbidden cloud tables.
ALTER TABLE cloud_enrich_policy ADD COLUMN generation INTEGER NOT NULL DEFAULT 1;
ALTER TABLE cloud_consent_receipts ADD COLUMN background_generation INTEGER NOT NULL DEFAULT 0;
-- A digest's server cursor orders replacements independently of pull/retry order.
ALTER TABLE cloud_digests ADD COLUMN server_sequence INTEGER NOT NULL DEFAULT 0;
ALTER TABLE cloud_digests ADD COLUMN server_stream TEXT NOT NULL DEFAULT '';
-- Selection metadata contains limits only, frozen per upload for exact rebuilds.
ALTER TABLE cloud_enrich_policy ADD COLUMN evidence_settings_json TEXT NOT NULL DEFAULT '';
ALTER TABLE cloud_consent_receipts ADD COLUMN evidence_settings_json TEXT NOT NULL DEFAULT '';
