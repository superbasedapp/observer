package seatbilling

import (
	"fmt"
	"time"
)

// ClosedPeriod returns the billing period that closed when the current one
// started, as receipt days (YYYY-MM-DD, end exclusive): the month before
// currentStart, by the calendar of currentStart's UTC day. It is the period
// whose seats the next renewal bills (plan 06 5.8.5, in arrears): the seat
// sync sets the quantity to that period's seats during the current period,
// and the renewal at its end charges it.
//
// currentStart is Paddle's current_billing_period.starts_at (RFC3339). A
// month back from the 31st follows Go's AddDate normalization (31 March
// minus one month is 3 March), so a short month yields a period a few days
// shorter; never longer than the period Paddle billed, and the seat union
// over it can only undercount, never bill a day twice.
func ClosedPeriod(currentStart string) (start, end string, err error) {
	t, err := time.Parse(time.RFC3339, currentStart)
	if err != nil {
		return "", "", fmt.Errorf("seatbilling.ClosedPeriod: %q: %w", currentStart, err)
	}
	day := time.Date(t.UTC().Year(), t.UTC().Month(), t.UTC().Day(), 0, 0, 0, 0, time.UTC)
	return day.AddDate(0, -1, 0).Format(time.DateOnly), day.Format(time.DateOnly), nil
}
