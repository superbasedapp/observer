// Compatibility shim: the Messages-table data model (sort vocabulary, column
// table, presets, persisted-sort reader, watch-follow rule) was promoted into
// the shared design system so the node and org session-detail Messages tables
// share one source. Existing @/...sessiondetail/messagesModel importers are
// unchanged.
export * from "@shared/lib/messagesModel";
