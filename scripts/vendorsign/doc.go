// Command vendorsign is the RELEASE-SIDE producer of the vendor
// artifact signature and the signed release manifest that wave W6 of
// docs/plans/enterprise-update-management-plan-2026-09-07.md specifies.
//
// It is the counterpart of two things already in the tree:
//
//   - cmd/observer/update_vendorsig.go, which verifies an artifact
//     signature on a node against a key compiled into the agent
//     (internal/update/vendorkey.go). This tool produces exactly the
//     bytes that verifier consumes: the RAW 64-byte Ed25519 signature
//     over the whole archive, written to a sibling `<archive>.sig`.
//     A container format (minisign, a cosign bundle) would be a
//     producer/verifier mismatch, because nothing unwraps one — which
//     is why neither is spellable in a manifest any more: the sig-type
//     vocabulary is exactly the set of schemes something verifies.
//   - internal/update.Verify, whose nine ordered rules judge a signed
//     manifest envelope. This tool emits an envelope of exactly that
//     shape, so `update-manifest-<channel>.json` is a first-class
//     object an org server can consume instead of scraping asset names.
//
// It lives under scripts/ because it runs in
// .github/workflows/npm-release.yml and nowhere else: no shipped binary
// imports it, and it must not import internal/orgserver (which is
// stripped from the public tree, so a scripts/ tool that depended on it
// would not build there).
//
// Verbs:
//
//	vendorsign keygen  -out DIR [-feed]
//	vendorsign sign    -key FILE ARCHIVE...
//	vendorsign manifest -key FILE -dir DIR -version vX.Y.Z -channel stable -out FILE
//	vendorsign osvexport -key FILE -in DIR -state DIR -out DIR [-manifest-version N]
//	vendorsign osvosexport -key FILE -in DIR -state DIR -out DIR [-manifest-version N]
//	vendorsign osvshards -key FILE [-lang DIR] [-os DIR] -state DIR -objects DIR -out DIR
//	vendorsign kev -key FILE -in FILE -state DIR -out DIR
//	vendorsign epss -key FILE -in FILE -state DIR -out DIR [-osv DIR]...
//	vendorsign secindex -kind security.malicious_packages -key FILE -osv-export DIR -state DIR -out DIR
//	vendorsign secindex -kind security.popular_names -key FILE -popular eco=FILE... -source TEXT
//	        -license SPDX -source-url URL -state DIR -out DIR
//
// (main.go's usage lists every verb.) keygen -feed mints the CONTENT-FEED
// key instead (content-feed.key, internal/update/contentfeedkey.go): it signs
// ClassFeed kinds only and lives only on the feed publisher host
// (/etc/sbo-feed), never as a repository secret. osvexport is that host's
// daily job (static feed mirroring plan section 6.2 and 6.3, osvexport.go):
// it turns the fetched OSV all.zip exports into a per-ecosystem base plus a
// cumulative delta and signs the security.osv_export manifest with the feed
// key. osvosexport is its sibling for the OS package databases (OS and CI
// scanning plan sections 6.4 and 6.6.1, osvosexport.go): it strips each
// distribution's whole export into one file per row of osvdb.OSReleases and
// publishes those the same way, as the security.osv_os_export kind.
// osvshards splits both kinds' inputs into the hash-prefix shards of
// remote matching (OS and CI scanning plan sections 13.3 and 13.11, lane
// RM-1; osvshards.go): content-addressed shards and index files in an
// object store the publisher uploads to the public shard bucket, and the
// signed security.osv_shards manifest naming each set's descriptor.
// kev and epss publish the exploit-likelihood kinds security.kev and
// security.epss (OS and CI scanning plan section 14.7; exploitkev.go,
// exploitepss.go, the shared small-feed path feedsingle.go): the CISA KEV
// catalog compacted, and the FIRST EPSS scores cut to the CVEs of the
// published OSV exports and quantized, in the formats internal/secexploit
// owns.
//
// The private key is a base64 32-byte Ed25519 seed on one line, held in
// the OBSERVER_VENDOR_SIGNING_KEY repository secret on the private
// origin. It is never in this tree, and every verb that needs it fails
// loudly rather than signing with anything improvised.
package main
