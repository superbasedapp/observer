package store

import (
	"context"
	"fmt"
)

// loadCloudSelectedTexts reads only enabled content categories in the caller's
// evidence snapshot. Assistant rows are prose only; reasoning, tool output,
// tool-call inputs, and sidechains never enter this selection.
func loadCloudSelectedTexts(ctx context.Context, db cloudReader, sessionID string, settings CloudEvidenceSettings, failures func(string)) (CloudSessionTexts, error) {
	var out CloudSessionTexts
	var err error
	if settings.UserMessages > 0 {
		out.UserPrompts, err = loadCloudPromptRows(ctx, db, sessionID)
		if err != nil {
			return out, err
		}
	}
	if settings.AssistantMessages > 0 {
		out.AssistantMessages, err = cloudTextRows(ctx, db, `
            WITH prose AS (
                SELECT substr(COALESCE(target, ''), 1, ?) AS body, timestamp, id,
                    ROW_NUMBER() OVER (PARTITION BY COALESCE(NULLIF(message_id, ''), 'row:' || id)
                        ORDER BY timestamp DESC, id DESC) AS message_part
                  FROM actions WHERE session_id = ? AND action_type = 'assistant_message'
                    AND COALESCE(target, '') <> ''`+notSidechain+`
            )
            SELECT body FROM prose WHERE message_part = 1
             ORDER BY timestamp DESC, id DESC LIMIT ?`, cloudTextScanBytes, sessionID, settings.AssistantMessages)
		if err != nil {
			return out, fmt.Errorf("store.loadCloudSelectedTexts: %w", err)
		}
		for i, j := 0, len(out.AssistantMessages)-1; i < j; i, j = i+1, j-1 {
			out.AssistantMessages[i], out.AssistantMessages[j] = out.AssistantMessages[j], out.AssistantMessages[i]
		}
	}
	if settings.FailureClasses > 0 && failures != nil {
		if err := streamCloudFailures(ctx, db, sessionID, failures); err != nil {
			return out, err
		}
	}
	return out, nil
}
