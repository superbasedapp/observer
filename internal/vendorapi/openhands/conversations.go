package openhands

import (
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceAppConversations is the catalog id of the conversation search.
const SurfaceAppConversations vs.SurfaceID = "openhands.cloud.app_conversations_search"

// Conversation vocabulary.
const (
	AppConversationsContract = "openhands.cloud.app_conversations_search/v1 cloud-api v1 reference 2026-10-31"

	// ConversationClass is the snapshot class of one conversation (the
	// session Observer shows); its subject is the conversation id.
	ConversationClass = "openhands.app_conversation"
	// UsageNamespace and UsageJoinKind key a conversation's accumulated
	// usage: one row per conversation, re-landed with a higher revision
	// (updated_at) as the conversation runs.
	UsageNamespace = "openhands.conversation"
	UsageJoinKind  = "conversation_id"
	// ChargedUnitUSD is the unit of accumulated_cost (provider-reported
	// dollars, never reconstructed from tokens).
	ChargedUnitUSD = "usd"
	// IdentityCaller names the API key owner when a conversation carries no
	// created_by_user_id: the search lists the caller's own conversations.
	IdentityCaller      = "caller"
	IdentityCallerValue = "self"
	// InputBasisFlag records that InputTokens is the vendor's prompt_tokens
	// as reported: whether it includes the cache-read and cache-write
	// tokens is not documented, so it is never netted here.
	InputBasisFlag  = "input_basis"
	InputBasisValue = "prompt_tokens_as_reported"
)

// AppConversations returns the driver of
// openhands.cloud.app_conversations_search.
//
// Contract (OpenHands Cloud V1, "Search App Conversations", reference
// sources OH01 and OH04): GET /api/v1/app-conversations/search with limit
// (at most 100), page_id (the previous next_page_id) and
// include_sub_conversations=true (the default omits child and subagent
// conversations); for an incremental run the window is sent as
// updated_at__gte and updated_at__lt (filter names Inferred). Response
// {items: [...], next_page_id}. Each conversation lands as one snapshot of
// class openhands.app_conversation (creator, repository and branch, trigger,
// model, statuses, parent and child ids, timestamps) and, when metrics are
// reported, one usage row keyed by the conversation id: prompt, completion,
// cache and reasoning tokens plus accumulated_cost in USD, revision
// updated_at. session_api_key and conversation_url (together a runtime
// credential for the sandbox agent-server) are never decoded.
func AppConversations() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceAppConversations,
		Build:           buildAppConversations,
		ParseResponse:   parseAppConversations,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassSessions, vs.ClassUsage, vs.ClassCost},
		ClosedDTO:       true,
		ContractVersion: AppConversationsContract,
		Tool:            Tool,
		KnownPaths:      appConversationsKnownPaths,
	}
}

func buildAppConversations(_ vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	q := map[string][]string{"include_sub_conversations": {"true"}}
	if err := windowQuery(SurfaceAppConversations, q, "updated_at", w); err != nil {
		return vendorapi.Request{}, err
	}
	if err := pageQuery(SurfaceAppConversations, q, cursor); err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{Method: "GET", Path: "/api/v1/app-conversations/search", Query: q}, nil
}

// conversation is the closed DTO of one conversation: session_api_key and
// conversation_url are deliberately absent.
type conversation struct {
	ID                   *string   `json:"id"`
	CreatedByUserID      *string   `json:"created_by_user_id"`
	SelectedRepository   *string   `json:"selected_repository"`
	SelectedBranch       *string   `json:"selected_branch"`
	GitProvider          *string   `json:"git_provider"`
	Title                *string   `json:"title"`
	Trigger              *string   `json:"trigger"`
	LLMModel             *string   `json:"llm_model"`
	SandboxStatus        *string   `json:"sandbox_status"`
	ExecutionStatus      *string   `json:"execution_status"`
	ParentConversationID *string   `json:"parent_conversation_id"`
	SubConversationIDs   *[]string `json:"sub_conversation_ids"`
	PRNumber             *[]num    `json:"pr_number"`
	CreatedAt            *string   `json:"created_at"`
	UpdatedAt            *string   `json:"updated_at"`
	Metrics              *struct {
		AccumulatedCost       *num `json:"accumulated_cost"`
		AccumulatedTokenUsage *struct {
			PromptTokens     *num `json:"prompt_tokens"`
			CompletionTokens *num `json:"completion_tokens"`
			CacheReadTokens  *num `json:"cache_read_tokens"`
			CacheWriteTokens *num `json:"cache_write_tokens"`
			ReasoningTokens  *num `json:"reasoning_tokens"`
		} `json:"accumulated_token_usage"`
	} `json:"metrics"`
}

// putShort sets an optional id-shaped body value, refusing an over-long one.
func putShort(body map[string]string, key string, v *string) bool {
	s := str(v)
	if s == "" {
		return true
	}
	if len(s) > vendorapi.MaxIDLen {
		return false
	}
	body[key] = s
	return true
}

func parseAppConversations(r vendorapi.Response) (vendorapi.Page, error) {
	var doc page[conversation]
	next, err := envelope(SurfaceAppConversations, r, &doc)
	if err != nil {
		return vendorapi.Page{}, err
	}
	out := vendorapi.Page{NextCursor: next, SourceRecords: len(*doc.Items)}
	seen := map[string]bool{}
	for i, c := range *doc.Items {
		id := str(c.ID)
		if !idRE.MatchString(id) {
			return vendorapi.Page{}, drift(SurfaceAppConversations, "items[%d].id is missing or not an id", i)
		}
		if seen[id] {
			return vendorapi.Page{}, drift(SurfaceAppConversations, "items[%d] repeats a conversation", i)
		}
		seen[id] = true
		created, ok := isoTime(c.CreatedAt)
		if !ok {
			return vendorapi.Page{}, drift(SurfaceAppConversations, "items[%d].created_at is not an ISO timestamp", i)
		}
		at := created
		body := map[string]string{"created_at": created.Format(time.RFC3339)}
		if c.UpdatedAt != nil {
			u, ok := isoTime(c.UpdatedAt)
			if !ok {
				return vendorapi.Page{}, drift(SurfaceAppConversations, "items[%d].updated_at is not an ISO timestamp", i)
			}
			at = u
			body["updated_at"] = u.Format(time.RFC3339)
		}
		if v, _ := capText(str(c.Title), maxBodyText); v != "" {
			body["title"] = v
		}
		for _, f := range []struct {
			key string
			v   *string
		}{
			{"created_by_user_id", c.CreatedByUserID},
			{"selected_repository", c.SelectedRepository},
			{"selected_branch", c.SelectedBranch},
			{"git_provider", c.GitProvider},
			{"trigger", c.Trigger},
			{"llm_model", c.LLMModel},
			{"sandbox_status", c.SandboxStatus},
			{"execution_status", c.ExecutionStatus},
			{"parent_conversation_id", c.ParentConversationID},
		} {
			if !putShort(body, f.key, f.v) {
				return vendorapi.Page{}, drift(SurfaceAppConversations, "items[%d].%s is over-long", i, f.key)
			}
		}
		if c.SubConversationIDs != nil {
			body["sub_conversation_count"] = strconv.Itoa(len(*c.SubConversationIDs))
		}
		if c.PRNumber != nil {
			body["pr_count"] = strconv.Itoa(len(*c.PRNumber))
			if len(*c.PRNumber) > 0 {
				n, ok := count(&(*c.PRNumber)[0])
				if !ok {
					return vendorapi.Page{}, drift(SurfaceAppConversations, "items[%d].pr_number has a value that is not a pull request number", i)
				}
				body["pr_number"] = strconv.FormatInt(n, 10)
			}
		}
		out.Snapshots = append(out.Snapshots, vendorapi.VendorSnapshot{Class: ConversationClass, Subject: id, Body: body})
		if c.Metrics == nil {
			continue
		}
		u := vendorapi.UsageRow{
			JoinKind: UsageJoinKind, JoinNamespace: UsageNamespace, JoinValue: id, At: at, SessionRef: id,
			Model: str(c.LLMModel), Revision: at.Unix(), IdentityKind: IdentityCaller, Identity: IdentityCallerValue,
			Flags: map[string]string{},
		}
		if v := str(c.CreatedByUserID); v != "" {
			u.IdentityKind, u.Identity = "user_id", v
		}
		if t := c.Metrics.AccumulatedTokenUsage; t != nil {
			var oks [5]bool
			u.InputTokens, oks[0] = count(t.PromptTokens)
			u.OutputTokens, oks[1] = count(t.CompletionTokens)
			u.CacheReadTokens, oks[2] = count(t.CacheReadTokens)
			u.CacheWriteTokens, oks[3] = count(t.CacheWriteTokens)
			u.ReasoningTokens, oks[4] = count(t.ReasoningTokens)
			for _, ok := range oks {
				if !ok {
					return vendorapi.Page{}, drift(SurfaceAppConversations, "items[%d].metrics.accumulated_token_usage has a count that is not a whole non-negative number", i)
				}
			}
			u.Flags[InputBasisFlag] = InputBasisValue
		}
		if c.Metrics.AccumulatedCost != nil {
			usd, ok := vendorapi.DecimalMicros(string(*c.Metrics.AccumulatedCost), 0)
			if !ok || usd < 0 {
				return vendorapi.Page{}, drift(SurfaceAppConversations, "items[%d].metrics.accumulated_cost is not a non-negative amount", i)
			}
			u.ChargedUnit, u.ChargedMicros = ChargedUnitUSD, usd
		}
		out.Usage = append(out.Usage, u)
	}
	return out, nil
}

// appConversationsKnownPaths are the response paths of the corpus field
// ledger of "Search App Conversations".
var appConversationsKnownPaths = []string{
	"items", "items[]", "items[].conversation_url", "items[].created_at", "items[].created_by_user_id",
	"items[].execution_status", "items[].git_provider", "items[].id", "items[].llm_model", "items[].metrics",
	"items[].metrics.accumulated_cost", "items[].metrics.accumulated_token_usage",
	"items[].metrics.accumulated_token_usage.cache_read_tokens",
	"items[].metrics.accumulated_token_usage.cache_write_tokens",
	"items[].metrics.accumulated_token_usage.completion_tokens",
	"items[].metrics.accumulated_token_usage.prompt_tokens",
	"items[].metrics.accumulated_token_usage.reasoning_tokens", "items[].parent_conversation_id",
	"items[].pr_number", "items[].pr_number[]", "items[].sandbox_id", "items[].sandbox_status",
	"items[].selected_branch", "items[].selected_repository", "items[].session_api_key",
	"items[].sub_conversation_ids", "items[].sub_conversation_ids[]", "items[].title", "items[].trigger",
	"items[].updated_at", "next_page_id",
}
