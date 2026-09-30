package store

import (
	"context"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/requestclass"
	"github.com/marmutapp/superbased-observer/internal/spendverdict"
)

// LoadSessionRequestClassSplit splits sessionID's counted proxy turns by the
// client-declared request class (api_turns.request_class, agent migration
// 144) through the shared pure internal/requestclass.Summarize. The org
// session drawer runs the same derivation over its copy of the rows
// (rollup.sessionRequestClassSplit), so both dashboards report the same split
// (lane G-WIRE2).
//
// "Counted" is the one session rule: sessionmsg.DeriveVerdicts over
// spendverdict.LoadSession's rows (the rows every node reader of a session
// derives from), so the split's turns are the session header's proxy turns.
// A counted proxy row carries its transcript twin's visible output
// (ProxyOutput) and its recorded proxy cost. Nil when the session has no
// counted proxy turn.
func (s *Store) LoadSessionRequestClassSplit(ctx context.Context, sessionID string) (*requestclass.Split, error) {
	rows, err := spendverdict.LoadSession(ctx, s.db, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadSessionRequestClassSplit: %w", err)
	}
	if len(rows.Proxies) == 0 {
		return nil, nil
	}
	classes := map[int64]string{}
	q, err := s.db.QueryContext(ctx,
		`SELECT id, COALESCE(request_class,'') FROM api_turns WHERE session_id = ?`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadSessionRequestClassSplit: classes: %w", err)
	}
	defer q.Close()
	for q.Next() {
		var id int64
		var class string
		if err := q.Scan(&id, &class); err != nil {
			return nil, fmt.Errorf("store.LoadSessionRequestClassSplit: scan: %w", err)
		}
		classes[id] = class
	}
	if err := q.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadSessionRequestClassSplit: rows: %w", err)
	}
	v := rows.Verdicts()
	in := make([]requestclass.Row, 0, len(rows.Proxies))
	for i, p := range rows.Proxies {
		if !v.ProxyCounted[i] {
			continue
		}
		in = append(in, requestclass.Row{
			Class:       classes[rows.ProxyIDs[i]],
			InputTokens: p.Input, OutputTokens: v.ProxyOutput[i],
			CacheReadTokens: p.CacheRead, CacheCreationTokens: p.CacheCreation,
			CostUSD: p.CostUSD,
		})
	}
	return requestclass.Summarize(in), nil
}
