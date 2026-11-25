package aws

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceQDeveloperEvents is the catalog id of the surface.
const SurfaceQDeveloperEvents vs.SurfaceID = "aws.cloudtrail.q_developer_events"

// Vocabulary.
const (
	QDeveloperEventsContract = "aws.cloudtrail.q_developer_events/v1 CloudTrail LookupEvents 2013-11-01 (2026-10-08)"

	// EventSource is the documented CloudTrail event source of Amazon Q
	// Developer ("Logging Amazon Q Developer API calls using AWS
	// CloudTrail").
	EventSource = "q.amazonaws.com"
	// AuditNamespace is the vendor audit namespace of these events.
	AuditNamespace = "aws.cloudtrail"
	// ActorUsername is the actor kind: CloudTrail's Username (an IAM user
	// name, a role session name or an Identity Center user), never an e-mail.
	ActorUsername = "aws_username"
	// Tool is the registry tool the events are attributed to: Kiro is the
	// successor of the Amazon Q Developer CLI and bills through the same
	// q.amazonaws.com subscriptions. The events also cover the Q Developer
	// IDE plugins and console, so attribution only resolves the actor.
	Tool = "kiro-cli"
	// ContentType is the AWS JSON 1.1 protocol media type.
	ContentType = "application/x-amz-json-1.1"
	// MaxWindow caps one run; Event history keeps 90 days.
	MaxWindow   = 31 * day
	MaxLookback = 90 * day
	day         = 24 * time.Hour
)

var (
	sigv4Auth = vendorapi.AuthContract{Kind: vs.AuthCloudIAM, Scheme: vendorapi.SchemeAWSSigV4}
	// eventNameRE is an IAM action name (CloudTrail EventName).
	eventNameRE = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,95}$`)
)

// QDeveloperEvents returns the driver of aws.cloudtrail.q_developer_events.
//
// Contract (AWS CloudTrail API Reference, LookupEvents; service model
// cloudtrail-2013-11-01, AWS JSON 1.1): POST / with X-Amz-Target
// CloudTrail_20131101.LookupEvents and the JSON body {LookupAttributes:
// [{AttributeKey: EventSource, AttributeValue: q.amazonaws.com}], StartTime,
// EndTime (epoch seconds, both inclusive), MaxResults (1 to 50), NextToken};
// response {Events: [{AccessKeyId, CloudTrailEvent, EventId, EventName,
// EventSource, EventTime, ReadOnly, Resources: [{ResourceName,
// ResourceType}], Username}], NextToken}, most recent first. AccessKeyId
// (credential metadata) and CloudTrailEvent (the whole event, with request
// parameters and response elements) are never decoded: the driver is
// closed-DTO and the row is may_return_secret.
func QDeveloperEvents() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceQDeveloperEvents,
		Build:           buildEvents,
		ParseResponse:   parseEvents,
		Auth:            sigv4Auth,
		ContentTypes:    []string{ContentType},
		Supplies:        []vs.DataClass{vs.ClassAudit},
		ClosedDTO:       true,
		ContractVersion: QDeveloperEventsContract,
		Tool:            Tool,
		MaxWindow:       MaxWindow,
		MaxLookback:     MaxLookback,
		KnownPaths: []string{
			"Events", "Events[]", "Events[].AccessKeyId", "Events[].CloudTrailEvent", "Events[].EventId",
			"Events[].EventName", "Events[].EventSource", "Events[].EventTime", "Events[].ReadOnly", "Events[].Resources",
			"Events[].Resources[]", "Events[].Resources[].ResourceName", "Events[].Resources[].ResourceType",
			"Events[].Username", "NextToken",
		},
	}
}

func buildEvents(_ vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	s := SurfaceQDeveloperEvents
	if w.From.IsZero() || !w.To.After(w.From) {
		return vendorapi.Request{}, fmt.Errorf("%s: a non-empty window is required", s)
	}
	if w.To.Sub(w.From) > MaxWindow {
		return vendorapi.Request{}, fmt.Errorf("%s: window longer than %s", s, MaxWindow)
	}
	if cursor != "" && !vendorapi.ValidOpaqueToken(cursor) {
		return vendorapi.Request{}, fmt.Errorf("%s: cursor is not an opaque NextToken", s)
	}
	body := vendorapi.CloudTrailLookup{
		EventSource: EventSource, StartSeconds: w.From.UTC().Unix(), EndSeconds: w.To.UTC().Unix(),
		MaxResults: vendorapi.MaxCloudTrailResults, NextToken: cursor,
	}
	return vendorapi.Request{Method: "POST", Path: "/", Body: body}, nil
}

// number is a JSON number kept as its literal text; a quoted value is a type
// change and fails the page.
type number string

// UnmarshalJSON accepts a bare JSON number only.
func (n *number) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || (b[0] != '-' && (b[0] < '0' || b[0] > '9')) {
		return fmt.Errorf("aws: %.16q is not a JSON number", b)
	}
	*n = number(b)
	return nil
}

// event is the closed DTO of one Event: AccessKeyId and CloudTrailEvent are
// deliberately absent.
type event struct {
	EventID     *string `json:"EventId"`
	EventName   *string `json:"EventName"`
	EventSource *string `json:"EventSource"`
	EventTime   *number `json:"EventTime"`
	ReadOnly    *string `json:"ReadOnly"`
	Resources   []struct {
		ResourceName *string `json:"ResourceName"`
		ResourceType *string `json:"ResourceType"`
	} `json:"Resources"`
	Username *string `json:"Username"`
}

type eventsDoc struct {
	Events    *[]event `json:"Events"`
	NextToken *string  `json:"NextToken"`
}

func drift(format string, a ...any) error {
	return vendorapi.Drift(SurfaceQDeveloperEvents, format, a...)
}

// epochTime reads an AWS JSON timestamp: epoch seconds, possibly with a
// fraction (the AWS JSON protocol's timestamp form).
func epochTime(n *number) (time.Time, bool) {
	if n == nil {
		return time.Time{}, false
	}
	f, err := strconv.ParseFloat(string(*n), 64)
	if err != nil || f < 0 || f > 253402300799 || math.IsNaN(f) {
		return time.Time{}, false
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(math.Round(frac*1e9))).UTC(), true
}

// snake turns an IAM action name into an audit action token (SendMessage ->
// send_message).
func snake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r + ('a' - 'A'))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func parseEvents(r vendorapi.Response) (vendorapi.Page, error) {
	if r.Status != 200 {
		return vendorapi.Page{}, drift("status %d is not the documented 200", r.Status)
	}
	var doc eventsDoc
	dec := json.NewDecoder(bytes.NewReader(r.Body))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return vendorapi.Page{}, drift("body does not decode as the documented response")
	}
	if doc.Events == nil {
		return vendorapi.Page{}, drift("required field Events is missing")
	}
	page := vendorapi.Page{}
	if doc.NextToken != nil && *doc.NextToken != "" {
		if !vendorapi.ValidOpaqueToken(*doc.NextToken) {
			return vendorapi.Page{}, drift("NextToken is not an opaque token")
		}
		if r.Cursor != "" && *doc.NextToken == r.Cursor {
			return vendorapi.Page{}, drift("NextToken repeats the token the page was asked with")
		}
		page.NextCursor = *doc.NextToken
	}
	seen := map[string]bool{}
	for i, e := range *doc.Events {
		id := vendorapi.TrimStr(e.EventID)
		if id == "" {
			return vendorapi.Page{}, drift("Events[%d].EventId is missing", i)
		}
		if seen[id] {
			return vendorapi.Page{}, drift("Events[%d] repeats an event", i)
		}
		seen[id] = true
		at, ok := epochTime(e.EventTime)
		if !ok {
			return vendorapi.Page{}, drift("Events[%d].EventTime is not an epoch time", i)
		}
		name := vendorapi.TrimStr(e.EventName)
		if !eventNameRE.MatchString(name) {
			return vendorapi.Page{}, drift("Events[%d].EventName is not an action name", i)
		}
		// The lookup asked for one event source; another is a contract change.
		if vendorapi.TrimStr(e.EventSource) != EventSource {
			return vendorapi.Page{}, drift("Events[%d].EventSource is not the requested source", i)
		}
		ev := vendorapi.AuditEvent{
			Namespace: AuditNamespace, EventID: id, At: at, Action: snake(name),
			Detail: map[string]string{"event_source": EventSource},
		}
		if u := vendorapi.TrimStr(e.Username); u != "" {
			ev.ActorKind, ev.ActorIdentity = ActorUsername, u
		}
		switch ro := vendorapi.TrimStr(e.ReadOnly); ro {
		case "true", "false":
			ev.Detail["read_only"] = ro
		case "":
		default:
			return vendorapi.Page{}, drift("Events[%d].ReadOnly is not true or false", i)
		}
		if len(e.Resources) > 0 {
			ev.Target = vendorapi.TrimStr(e.Resources[0].ResourceName)
			if t := vendorapi.TrimStr(e.Resources[0].ResourceType); t != "" {
				ev.Detail["resource_type"] = t
			}
		}
		page.Audit = append(page.Audit, ev)
	}
	return page, nil
}
