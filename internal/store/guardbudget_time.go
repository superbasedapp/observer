package store

import "time"

// UTC RFC3339Nano strings omit trailing fractional zeros. Normalizing their
// precision preserves ordering at exact and fractional window boundaries;
// for example 00:00:00.1Z otherwise sorts before 00:00:00Z.
const guardBudgetTimestampOrderSQL = `substr(timestamp,1,19) || '.' ||
	CASE WHEN substr(timestamp,20,1) = '.'
	THEN substr(substr(timestamp,21,length(timestamp)-21)||'000000000',1,9)
	ELSE '000000000' END || 'Z'`

// The raw timestamp lower bound preserves the existing timestamp index for
// advisory reads. The second predicate refines the first second exactly.
// Managed reads additionally inspect malformed history, which cannot be
// assigned to any window. Keeping that OR out of advisory SQL is necessary:
// SQLite does not remove a parameter-gated malformed-history scan branch.
const guardBudgetBoundedWhereSQL = `
	WHERE ((? <> '' AND session_id = ?)
	OR (timestamp >= ? AND (` + guardBudgetTimestampOrderSQL + `) >= ?))`

const guardBudgetManagedWhereSQL = guardBudgetBoundedWhereSQL + `
	OR (` + guardBudgetInvalidTimestampSQL + `)`

func guardBudgetUsageWhere(managed bool) string {
	if managed {
		return guardBudgetManagedWhereSQL
	}
	return guardBudgetBoundedWhereSQL
}

func guardBudgetWindowStamp(at time.Time) string {
	if at.IsZero() {
		at = time.Now()
	}
	return at.UTC().Format("2006-01-02T15:04:05.000000000Z")
}

func nextGuardBudgetWeeklyExpiry(current time.Time, stamp string, amount float64) time.Time {
	if amount <= 0 {
		return current
	}
	at, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil || at.IsZero() {
		return current
	}
	expiry := at.Add(7 * 24 * time.Hour)
	if current.IsZero() || expiry.Before(current) {
		return expiry
	}
	return current
}

// All canonical store writers use UTC RFC3339Nano. Managed accounting rejects
// other encodings because window comparisons are lexical. SQLite accepts dates,
// Julian numbers and overflowing dates which Go's RFC3339 parser rejects; a
// julianday-only validity check would let malformed historical rows disappear
// before pricing or token accounting could mark their windows unavailable.
// This constant is shared by the two static accounting queries, never built
// from caller input. Fractional seconds may contain one through nine digits.
const guardBudgetInvalidTimestampSQL = `
	 timestamp IS NULL OR julianday(timestamp) IS NULL
	 OR substr(timestamp,1,19) != strftime('%Y-%m-%dT%H:%M:%S',substr(timestamp,1,19)||'Z','+0 seconds')
	 OR substr(timestamp,1,19) = '0001-01-01T00:00:00'
	 OR substr(timestamp,12,2) NOT BETWEEN '00' AND '23'
	 OR substr(timestamp,15,2) NOT BETWEEN '00' AND '59'
	 OR substr(timestamp,18,2) NOT BETWEEN '00' AND '59'
	 OR NOT (
	   (length(timestamp) = 20 AND substr(timestamp,20,1) = 'Z')
	   OR (length(timestamp) BETWEEN 22 AND 30 AND substr(timestamp,20,1) = '.'
	       AND substr(timestamp,-1) = 'Z'
	       AND substr(timestamp,21,length(timestamp)-21) NOT GLOB '*[^0-9]*')
	 )`
