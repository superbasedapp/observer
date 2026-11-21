package openshellorg

// The worker's end of a run's row (lane FX6, F-P7-1). A run the
// organization ends (an admin revoke, a drain, the reaper's own rows) races
// the node's end report and the front's ending event: the worker read the
// row as created, collected and deleted the box, and meanwhile the node
// moved the row to ending, so the worker's move "from created" was refused
// and the row stayed ending with no end reason until a later pass settled
// it with that pass's reason. The worker now settles from the state the row
// is in when it writes (SettleTarget), and the end reason the row already
// carries is kept (KeptEndReason): the first true reason wins, and a later
// pass never overwrites it.

// settleRow is one row of the settle table: a row in From, ended for
// Reason ("" matches any reason), moves To.
type settleRow struct {
	From   BoxState
	Reason EndReason
	To     BoxState
}

// settleTable is walked top-down. collect_failed is not in it: only an
// admin decision, drain --force or delete_unstoppable leave that state
// (G1-R43), through their own moves.
var settleTable = []settleRow{
	{BoxHeld, EndHoldExpired, BoxExpired},
	{BoxEnding, "", BoxEnded},
	{BoxMinted, "", BoxReaped},
	{BoxCreated, "", BoxReaped},
	{BoxHolding, "", BoxReaped},
	{BoxHeld, "", BoxReaped},
	{BoxResuming, "", BoxReaped},
}

// SettleTarget is the terminal state the worker moves a row in from to,
// ending it for reason. False when the worker has no settle from that state
// (a terminal row, or collect_failed).
func SettleTarget(from BoxState, reason EndReason) (BoxState, bool) {
	for _, r := range settleTable {
		if r.From == from && (r.Reason == "" || r.Reason == reason) {
			return r.To, true
		}
	}
	return "", false
}

// KeptEndReason is the end reason a settle writes: the one the row already
// carries (claimed when the organization committed to ending it, or a
// member's discard request), else the settle's own. The first true reason
// is kept.
func KeptEndReason(stored, proposed EndReason) EndReason {
	if stored != "" {
		return stored
	}
	return proposed
}
