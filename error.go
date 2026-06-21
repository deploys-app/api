package api

import (
	"context"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/moonrhythm/validator"
)

// Errors is the application-error resource: grouped, deduplicated stack traces
// ("issues") detected from a deployment's output — mined from the durable log
// stream by the capture agent and/or reported directly via Create. Issues carry
// a triage lifecycle (open → resolved → reopened, or muted).
//
// Named in the plural because the singular Error is already a Status constant.
type Errors interface {
	// List requires the `error.list` permission. It lists error issues filtered
	// by triage Status and paged with Cursor. Scope by Name (one deployment) or
	// omit Name to list every deployment's issues across the project (a
	// project-wide errors view); each issue carries its Deployment + Location.
	// Best-effort, like DeploymentLogsHistory.
	List(ctx context.Context, m *ErrorList) (*ErrorListResult, error)
	// Get requires the `error.get` permission. It returns one error issue with
	// its representative stack trace and recent occurrence pointers (for
	// deep-linking back into LogsHistory).
	Get(ctx context.Context, m *ErrorGet) (*ErrorGetResult, error)
	// Update requires the `error.update` permission. It changes an error issue's
	// triage status: resolve, reopen, or mute.
	Update(ctx context.Context, m *ErrorUpdate) (*Empty, error)
	// Create requires the `error.create` permission. It reports one or more
	// application errors for a deployment directly (instead of relying on
	// log-mining). Reported events are fingerprinted with the same function as
	// mined traces, so a report and a mined trace with the same signature merge
	// into one issue.
	Create(ctx context.Context, m *ErrorCreate) (*ErrorCreateResult, error)
}

// Error-issue triage statuses. An issue is born "open"; a human (or the system)
// can "resolve" it, and a later occurrence after resolution reopens it
// (regression). "muted" silences notifications while still counting occurrences.
const (
	ErrorStatusOpen     = "open"
	ErrorStatusResolved = "resolved"
	ErrorStatusMuted    = "muted"
)

// ErrorStatusAll is a list-filter sentinel (not a stored status) that returns
// issues in every status.
const ErrorStatusAll = "all"

// Error-issue list orderings.
const (
	ErrorSortLastSeen  = "lastSeen"  // most recently seen first (default)
	ErrorSortFirstSeen = "firstSeen" // newest issues first
	ErrorSortCount     = "count"     // most frequent first
)

// Error-issue kinds — the language/runtime family the stack trace was parsed as.
// Emitted by the capture-side reassembler or supplied by a Create report;
// "generic" is the heuristic fallback when no language-specific frames are known.
const (
	ErrorKindGo      = "go"
	ErrorKindJava    = "java"
	ErrorKindPython  = "python"
	ErrorKindNode    = "node"
	ErrorKindRuby    = "ruby"
	ErrorKindGeneric = "generic"
)

// ErrorList lists detected application error issues — stack traces grouped and
// deduplicated by a stable fingerprint. Scope to one deployment with
// Location+Name, or omit Name to list every deployment's issues across the
// project (a project-wide errors view).
type ErrorList struct {
	Project string `json:"project" yaml:"project"`
	// Location and Name scope the listing to one deployment. Omit Name to list
	// issues across every deployment in the project; Location is then optional
	// and, if set, narrows to that location. When Name is set, Location is
	// required.
	Location string `json:"location" yaml:"location"`
	Name     string `json:"name" yaml:"name"`
	// Status filters by triage status: "open" (default), "resolved", "muted", or
	// "all". Empty defaults to "open".
	Status string `json:"status" yaml:"status"`
	// Limit bounds the number of issues returned in this page. 0 defaults to
	// ErrorListDefaultLimit; otherwise it is clamped to [1, ErrorListMaxLimit].
	Limit int `json:"limit" yaml:"limit"`
	// Cursor pages through the result; empty starts at the first page. It is an
	// opaque server token — pass back the previous response's NextCursor.
	Cursor string `json:"cursor" yaml:"cursor"`
	// Sort orders the issues: "lastSeen" (default), "firstSeen", or "count".
	Sort string `json:"sort" yaml:"sort"`
}

func (m *ErrorList) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	m.Location = strings.TrimSpace(m.Location)
	m.Status = strings.TrimSpace(m.Status)
	m.Cursor = strings.TrimSpace(m.Cursor)
	m.Sort = strings.TrimSpace(m.Sort)

	switch {
	case m.Limit == 0:
		m.Limit = ErrorListDefaultLimit
	case m.Limit < 1:
		m.Limit = 1
	case m.Limit > ErrorListMaxLimit:
		m.Limit = ErrorListMaxLimit
	}

	v := validator.New()

	v.Must(m.Project != "", "project required")
	// Name scopes to one deployment (then Location is required); omitting Name
	// lists the whole project, with Location an optional location filter.
	if m.Name != "" {
		v.Must(m.Location != "", "location required when name is set")
		v.Must(ReValidName.MatchString(m.Name), "name invalid "+ReValidNameStr)
		// allow old spec long name
		v.Mustf(utf8.RuneCountInString(m.Name) <= DeploymentMaxNameLength*2, "name must have length less then %d characters", DeploymentMaxNameLength*2)
	}
	v.Must(validErrorListStatus(m.Status), "status invalid")
	v.Must(validErrorSort(m.Sort), "sort invalid")

	return WrapValidate(v)
}

type ErrorListResult struct {
	Issues []ErrorIssue `json:"issues" yaml:"issues"`
	// NextCursor is non-empty when more issues remain; pass it back as Cursor to
	// fetch the next page. Empty means the result is exhausted.
	NextCursor string `json:"nextCursor" yaml:"nextCursor"`
}

func (m *ErrorListResult) Table() [][]string {
	table := [][]string{
		{"ID", "DEPLOYMENT", "KIND", "STATUS", "COUNT", "LAST SEEN", "TITLE"},
	}
	for _, x := range m.Issues {
		last := ""
		if !x.LastSeen.IsZero() {
			last = x.LastSeen.UTC().Format(time.RFC3339)
		}
		table = append(table, []string{x.ID, x.Deployment, x.Kind, x.Status, strconv.Itoa(int(x.Count)), last, x.Title})
	}
	return table
}

// ErrorIssue is the summary view of one grouped error — a distinct stack-trace
// fingerprint seen one or more times.
type ErrorIssue struct {
	ID string `json:"id" yaml:"id"`
	// Deployment and Location identify the issue's deployment. Always populated;
	// the project-wide listing (request Name omitted) relies on them to show and
	// link each row to its deployment.
	Deployment  string    `json:"deployment" yaml:"deployment"`
	Location    string    `json:"location" yaml:"location"`
	Fingerprint string    `json:"fingerprint" yaml:"fingerprint"`
	Kind        string    `json:"kind" yaml:"kind"`
	Title       string    `json:"title" yaml:"title"`
	Status      string    `json:"status" yaml:"status"`
	Count       int64     `json:"count" yaml:"count"`
	FirstSeen   time.Time `json:"firstSeen" yaml:"firstSeen"`
	LastSeen    time.Time `json:"lastSeen" yaml:"lastSeen"`
	// SamplePod is the pod of the representative occurrence.
	SamplePod string `json:"samplePod" yaml:"samplePod"`
}

// ErrorGet fetches one error issue in full (sample stack + recent occurrence
// pointers) by ID.
type ErrorGet struct {
	Project  string `json:"project" yaml:"project"`
	Location string `json:"location" yaml:"location"`
	Name     string `json:"name" yaml:"name"`
	ID       string `json:"id" yaml:"id"`
}

func (m *ErrorGet) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	m.ID = strings.TrimSpace(m.ID)

	v := validator.New()

	v.Must(m.Location != "", "location required")
	v.Must(ReValidName.MatchString(m.Name), "name invalid "+ReValidNameStr)
	v.Mustf(utf8.RuneCountInString(m.Name) <= DeploymentMaxNameLength*2, "name must have length less then %d characters", DeploymentMaxNameLength*2)
	v.Must(m.Project != "", "project required")
	v.Must(m.ID != "", "id required")

	return WrapValidate(v)
}

type ErrorGetResult struct {
	Issue ErrorIssueDetail `json:"issue" yaml:"issue"`
}

func (m *ErrorGetResult) Table() [][]string {
	i := m.Issue
	first, last := "", ""
	if !i.FirstSeen.IsZero() {
		first = i.FirstSeen.UTC().Format(time.RFC3339)
	}
	if !i.LastSeen.IsZero() {
		last = i.LastSeen.UTC().Format(time.RFC3339)
	}
	return [][]string{
		{"FIELD", "VALUE"},
		{"id", i.ID},
		{"kind", i.Kind},
		{"status", i.Status},
		{"count", strconv.Itoa(int(i.Count))},
		{"firstSeen", first},
		{"lastSeen", last},
		{"title", i.Title},
	}
}

// ErrorIssueDetail is the full view: the summary plus a representative stack
// trace and recent occurrence pointers that deep-link into LogsHistory.
type ErrorIssueDetail struct {
	ErrorIssue
	// SampleMessage is the representative reassembled stack trace.
	SampleMessage string `json:"sampleMessage" yaml:"sampleMessage"`
	// RecentEvents are the most recent occurrence pointers (bounded), newest-first.
	RecentEvents []ErrorOccurrence `json:"recentEvents" yaml:"recentEvents"`
}

// ErrorOccurrence locates a single occurrence of an issue in the durable log
// store, so a viewer can jump to the surrounding logs. A directly-reported
// occurrence (via Create) has no backing log object, so Object/Offset are empty.
type ErrorOccurrence struct {
	Pod       string    `json:"pod" yaml:"pod"`
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`
	// Object + Offset address the source line in object storage (the error-event
	// object key and the line index within it).
	Object string `json:"object" yaml:"object"`
	Offset int    `json:"offset" yaml:"offset"`
}

// ErrorUpdate changes an error issue's triage status.
type ErrorUpdate struct {
	Project  string `json:"project" yaml:"project"`
	Location string `json:"location" yaml:"location"`
	Name     string `json:"name" yaml:"name"`
	ID       string `json:"id" yaml:"id"`
	// Status is the new triage status: "resolved", "open" (reopen), or "muted".
	Status string `json:"status" yaml:"status"`
}

func (m *ErrorUpdate) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	m.ID = strings.TrimSpace(m.ID)
	m.Status = strings.TrimSpace(m.Status)

	v := validator.New()

	v.Must(m.Location != "", "location required")
	v.Must(ReValidName.MatchString(m.Name), "name invalid "+ReValidNameStr)
	v.Mustf(utf8.RuneCountInString(m.Name) <= DeploymentMaxNameLength*2, "name must have length less then %d characters", DeploymentMaxNameLength*2)
	v.Must(m.Project != "", "project required")
	v.Must(m.ID != "", "id required")
	v.Must(validErrorStatus(m.Status), "status must be resolved, open, or muted")

	return WrapValidate(v)
}

// ErrorCreate reports one or more application errors for a deployment directly,
// instead of relying on log-mining. Requires the `error.create` permission. Each
// reported event is fingerprinted and merged into the same issues as log-mined
// traces, so a reported error and a mined trace with the same signature collapse
// into one issue.
type ErrorCreate struct {
	Project  string `json:"project" yaml:"project"`
	Location string `json:"location" yaml:"location"`
	// Name is the deployment the errors are attributed to.
	Name   string        `json:"name" yaml:"name"`
	Events []ErrorReport `json:"events" yaml:"events"`
}

func (m *ErrorCreate) Valid() error {
	m.Location = strings.TrimSpace(m.Location)
	m.Name = strings.TrimSpace(m.Name)

	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Location != "", "location required")
	v.Must(ReValidName.MatchString(m.Name), "name invalid "+ReValidNameStr)
	v.Mustf(utf8.RuneCountInString(m.Name) <= DeploymentMaxNameLength*2, "name must have length less then %d characters", DeploymentMaxNameLength*2)
	v.Must(len(m.Events) > 0, "events required")
	v.Mustf(len(m.Events) <= ErrorCreateMaxEvents, "events must not exceed %d", ErrorCreateMaxEvents)
	for i := range m.Events {
		e := &m.Events[i]
		e.Kind = strings.TrimSpace(e.Kind)
		e.Type = strings.TrimSpace(e.Type)
		v.Mustf(e.Type != "", "events[%d].type required", i)
		v.Mustf(validErrorKind(e.Kind), "events[%d].kind invalid", i)
		v.Mustf(utf8.RuneCountInString(e.Type) <= ErrorReportMaxTypeLength, "events[%d].type too long", i)
		v.Mustf(len(e.Frames) <= ErrorReportMaxFrames, "events[%d].frames must not exceed %d", i, ErrorReportMaxFrames)
	}

	return WrapValidate(v)
}

// ErrorReport is one reported error within an ErrorCreate batch. It mirrors the
// fields of ErrorEvent that a reporter can supply; the server stamps the rest.
type ErrorReport struct {
	// Kind is the language/runtime family (see ErrorKind*); empty defaults to
	// "generic".
	Kind string `json:"kind" yaml:"kind"`
	// Type is the exception/panic class, e.g. "TypeError" or "panic". It is the
	// fingerprint basis when no Frames are supplied, and the only field surfaced
	// in notifications — keep it free of dynamic or secret data.
	Type string `json:"type" yaml:"type"`
	// Title is an optional display line (type + first message). Stored on the
	// issue detail but never placed in a notification.
	Title string `json:"title" yaml:"title"`
	// Frames are the stack frames, innermost-first; the fingerprint basis.
	Frames []ErrorFrame `json:"frames" yaml:"frames"`
	// Sample is the full stack-trace text; truncated server-side to
	// ErrorSampleMaxBytes.
	Sample string `json:"sample" yaml:"sample"`
	// Pod is the reporting instance/host; empty defaults to "reported".
	Pod string `json:"pod" yaml:"pod"`
	// Timestamp is when the error occurred; zero defaults to server-now.
	Timestamp time.Time `json:"ts" yaml:"ts"`
}

type ErrorCreateResult struct {
	// Issues lists, one per distinct fingerprint in the batch, the issue each
	// reported event landed in.
	Issues []ErrorCreateIssueRef `json:"issues" yaml:"issues"`
}

// ErrorCreateIssueRef points at the issue a reported event was merged into.
type ErrorCreateIssueRef struct {
	ID          string `json:"id" yaml:"id"`
	Fingerprint string `json:"fingerprint" yaml:"fingerprint"`
	Status      string `json:"status" yaml:"status"`
}

// ErrorEvent is the capture→apiserver wire contract: one structured error,
// parsed by the capture-side reassembler from the live log stream and written to
// the per-deployment error-event object stream. apiserver reads these to compute
// the fingerprint and aggregate into issues. The same shape backs a Create
// report. Versioned like the log-line contract; keep in sync with the
// log-capture writer.
type ErrorEvent struct {
	Deployment string       `json:"deployment"`
	Pod        string       `json:"pod"`
	Timestamp  time.Time    `json:"ts"`
	Kind       string       `json:"kind"`   // see ErrorKind*
	Type       string       `json:"type"`   // exception/panic class, no dynamic message
	Title      string       `json:"title"`  // type + first message line, display-only
	Frames     []ErrorFrame `json:"frames"` // innermost-first; the fingerprint basis
	Sample     string       `json:"sample"` // full reassembled trace, capped
}

// ErrorFrame is one parsed stack frame in an ErrorEvent.
type ErrorFrame struct {
	Func string `json:"func"`
	File string `json:"file"`
	Line int    `json:"line"`
}

func validErrorStatus(s string) bool {
	switch s {
	case ErrorStatusOpen, ErrorStatusResolved, ErrorStatusMuted:
		return true
	}
	return false
}

func validErrorListStatus(s string) bool {
	return s == "" || s == ErrorStatusAll || validErrorStatus(s)
}

func validErrorSort(s string) bool {
	switch s {
	case "", ErrorSortLastSeen, ErrorSortFirstSeen, ErrorSortCount:
		return true
	}
	return false
}

func validErrorKind(s string) bool {
	switch s {
	case "", ErrorKindGo, ErrorKindJava, ErrorKindPython, ErrorKindNode, ErrorKindRuby, ErrorKindGeneric:
		return true
	}
	return false
}
