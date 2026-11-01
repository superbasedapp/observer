// Package sandboxrelayd is the host side of the capture relay (sandbox plan
// v2 section 5.2; ledger rows SBX-BE-2, SBX-BE-13 and SBX-BE-18): the run
// records, the confined reader a relayed hook reads payload-named paths
// through, the daemon's per-run handler, the host helper's forwarder and the
// box-side client. The wire protocol is internal/sandboxrelay (pure); this
// package adds the file and socket I/O around it.
//
// The topology on a same-kernel row (bwrap today):
//
//	box: observer hook (relay client)
//	  -> relay.sock in the per-run socket dir (bound read-only in the box)
//	host: observer sandbox-host (forwarder; verifies every box frame)
//	  -> the daemon's owner-only relay endpoint (internal/localipc, under
//	     the observer directory, which the box never sees)
//	daemon: Handler (one per run, chosen by the channel) -> the injected
//	  Executor, which runs the hook pipeline host-side on the daemon path
//	  of internal/hookctx.
//
// The run identity is the channel's: the box channel is keyed by the run's
// box secret and the link by the run's link secret, and both secrets live
// in a run record only the host can read (RunRecord, under the observer
// directory). Nothing in a frame body names a run.
package sandboxrelayd
