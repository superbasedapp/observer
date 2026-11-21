package openshellorg

// Quotas are the org's per-member and org-wide box limits (sections 2.5,
// 3.6 and 7.3). The zero value is not usable; start from DefaultQuotas.
type Quotas struct {
	MaxConcurrentPerMember   int
	MaxConcurrentOrg         int
	MaxBoxesPerMember        int
	MaxHeldPerMember         int
	MaxHeldOrg               int
	DailyBoxMinutesPerMember int
	MaxRunMinutes            int
	BoxCPU                   int
	BoxMemoryMiB             int
	MaxHoldHours             int
}

// DefaultQuotas are the design defaults of section 2.5.
func DefaultQuotas() Quotas {
	return Quotas{
		MaxConcurrentPerMember: 2, MaxConcurrentOrg: 20, MaxBoxesPerMember: 3,
		MaxHeldPerMember: 2, MaxHeldOrg: 40, DailyBoxMinutesPerMember: 480,
		MaxRunMinutes: 120, BoxCPU: 2, BoxMemoryMiB: 4096, MaxHoldHours: 24,
	}
}

// Usage is the ledger's current counts for one member and the org. Live
// counts boxes in minted, created, resuming and ending; held counts holding,
// held and collect_failed (a collect_failed box still counts, section 7.3).
type Usage struct {
	MemberLive int
	MemberHeld int
	OrgLive    int
	OrgHeld    int
	// MemberMinutesToday is the member's reserved plus settled running
	// minutes for the current UTC day.
	MemberMinutesToday int
}

// quotaRow is one row of a quota table.
type quotaRow struct {
	Reason Reason
	Over   func(q Quotas, u Usage) bool
}

// createQuotaTable is T6's quota check for a new box, walked top-down.
var createQuotaTable = []quotaRow{
	{ReasonQuotaConcurrent, func(q Quotas, u Usage) bool { return u.MemberLive+1 > q.MaxConcurrentPerMember }},
	{ReasonQuotaOrgConcurrent, func(q Quotas, u Usage) bool { return u.OrgLive+1 > q.MaxConcurrentOrg }},
	{ReasonQuotaBoxes, func(q Quotas, u Usage) bool { return u.MemberLive+u.MemberHeld+1 > q.MaxBoxesPerMember }},
	{ReasonQuotaDailyMinutes, func(q Quotas, u Usage) bool {
		return u.MemberMinutesToday+q.MaxRunMinutes > q.DailyBoxMinutesPerMember
	}},
}

// resumeQuotaTable is T7r's quota check: the held box becomes live, so the
// member's live and held total does not grow.
var resumeQuotaTable = []quotaRow{
	{ReasonQuotaConcurrent, func(q Quotas, u Usage) bool { return u.MemberLive+1 > q.MaxConcurrentPerMember }},
	{ReasonQuotaOrgConcurrent, func(q Quotas, u Usage) bool { return u.OrgLive+1 > q.MaxConcurrentOrg }},
	{ReasonQuotaBoxes, func(q Quotas, u Usage) bool { return u.MemberLive+u.MemberHeld > q.MaxBoxesPerMember }},
	{ReasonQuotaDailyMinutes, func(q Quotas, u Usage) bool {
		return u.MemberMinutesToday+q.MaxRunMinutes > q.DailyBoxMinutesPerMember
	}},
}

// holdQuotaTable is the hold move's quota check: a live box becomes held.
var holdQuotaTable = []quotaRow{
	{ReasonHoldUnavailable, func(q Quotas, u Usage) bool { return u.MemberHeld+1 > q.MaxHeldPerMember }},
	{ReasonHoldUnavailable, func(q Quotas, u Usage) bool { return u.OrgHeld+1 > q.MaxHeldOrg }},
	{ReasonHoldUnavailable, func(q Quotas, u Usage) bool { return u.MemberLive+u.MemberHeld > q.MaxBoxesPerMember }},
}

func walkQuota(t []quotaRow, q Quotas, u Usage) Reason {
	for _, r := range t {
		if r.Over(q, u) {
			return r.Reason
		}
	}
	return ReasonNone
}

// CheckCreateQuota is T6's quota half for a new reservation.
func CheckCreateQuota(q Quotas, u Usage) Reason { return walkQuota(createQuotaTable, q, u) }

// CheckResumeQuota is T7r's quota half.
func CheckResumeQuota(q Quotas, u Usage) Reason { return walkQuota(resumeQuotaTable, q, u) }

// CheckHoldQuota is the hold move's quota half. Its only refusal is
// ReasonHoldUnavailable (rule E1 and the H triggers).
func CheckHoldQuota(q Quotas, u Usage) Reason { return walkQuota(holdQuotaTable, q, u) }

// Reservation is a box's minute bookkeeping on the ledger: a create reserves
// max_run_minutes; the end settles the real minutes (the hosted ledger's
// reserve and settle).
type Reservation struct {
	ReservedMinutes int
	SettledMinutes  int
	Settled         bool
}

// Reserve opens a reservation of the run's lower cap.
func Reserve(q Quotas) Reservation { return Reservation{ReservedMinutes: q.MaxRunMinutes} }

// Settle closes a reservation with the real running minutes, never below
// zero and never above the reservation's cap; settling twice keeps the first.
func Settle(r Reservation, realMinutes int) Reservation {
	if r.Settled {
		return r
	}
	if realMinutes < 0 {
		realMinutes = 0
	}
	if r.ReservedMinutes > 0 && realMinutes > r.ReservedMinutes {
		realMinutes = r.ReservedMinutes
	}
	r.SettledMinutes, r.Settled = realMinutes, true
	return r
}

// Counted is what a reservation counts against the daily quota: the reserve
// while open, the real minutes once settled.
func (r Reservation) Counted() int {
	if r.Settled {
		return r.SettledMinutes
	}
	return r.ReservedMinutes
}
