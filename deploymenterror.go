package api

import (
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/moonrhythm/validator"
)

// Error-issue triage statuses. An issue is born "open"; a human (or the system)
// can "resolve" it, and a later occurrence after resolution reopens it
// (regression). "muted" silences notifications while still counting occurrences.
const (
	DeploymentErrorStatusOpen     = "open"
	DeploymentErrorStatusResolved = "resolved"
	DeploymentErrorStatusMuted    = "muted"
)

// DeploymentErrorStatusAll is a list-filter sentinel (not a stored status) that
// returns issues in every status.
const DeploymentErrorStatusAll = "all"

// Error-issue list orderings.
const (
	DeploymentErrorSortLastSeen  = "lastSeen"  // most recently seen first (default)
	DeploymentErrorSortFirstSeen = "firstSeen" // newest issues first
	DeploymentErrorSortCount     = "count"     // most frequent first
)

// Error-issue kinds — the language/runtime family the stack trace was parsed as.
// Emitted by the capture-side reassembler; "generic" is the heuristic fallback
// when no language-specific frames could be parsed.
const (
	DeploymentErrorKindGo      = "go"
	DeploymentErrorKindJava    = "java"
	DeploymentErrorKindPython  = "python"
	DeploymentErrorKindNode    = "node"
	DeploymentErrorKindRuby    = "ruby"
	DeploymentErrorKindGeneric = "generic"
)

// DeploymentErrors lists detected application error issues — stack traces mined
// from the durable log stream, grouped and deduplicated by a stable fingerprint.
// Scope to one deployment with Location+Name, or omit Name to list every
// deployment's issues across the project (a project-wide errors view).
// History-backed and best-effort, like DeploymentLogsHistory.
type DeploymentErrors struct {
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
	// DeploymentErrorsDefaultLimit; otherwise it is clamped to
	// [1, DeploymentErrorsMaxLimit].
	Limit int `json:"limit" yaml:"limit"`
	// Cursor pages through the result; empty starts at the first page. It is an
	// opaque server token — pass back the previous response's NextCursor.
	Cursor string `json:"cursor" yaml:"cursor"`
	// Sort orders the issues: "lastSeen" (default), "firstSeen", or "count".
	Sort string `json:"sort" yaml:"sort"`
}

func (m *DeploymentErrors) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	m.Location = strings.TrimSpace(m.Location)
	m.Status = strings.TrimSpace(m.Status)
	m.Cursor = strings.TrimSpace(m.Cursor)
	m.Sort = strings.TrimSpace(m.Sort)

	switch {
	case m.Limit == 0:
		m.Limit = DeploymentErrorsDefaultLimit
	case m.Limit < 1:
		m.Limit = 1
	case m.Limit > DeploymentErrorsMaxLimit:
		m.Limit = DeploymentErrorsMaxLimit
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
	v.Must(validDeploymentErrorListStatus(m.Status), "status invalid")
	v.Must(validDeploymentErrorSort(m.Sort), "sort invalid")

	return WrapValidate(v)
}

type DeploymentErrorsResult struct {
	Issues []DeploymentErrorIssue `json:"issues" yaml:"issues"`
	// NextCursor is non-empty when more issues remain; pass it back as Cursor to
	// fetch the next page. Empty means the result is exhausted.
	NextCursor string `json:"nextCursor" yaml:"nextCursor"`
}

func (m *DeploymentErrorsResult) Table() [][]string {
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

// DeploymentErrorIssue is the summary view of one grouped error — a distinct
// stack-trace fingerprint seen one or more times.
type DeploymentErrorIssue struct {
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

// DeploymentErrorGet fetches one error issue in full (sample stack + recent
// occurrence pointers) by ID.
type DeploymentErrorGet struct {
	Project  string `json:"project" yaml:"project"`
	Location string `json:"location" yaml:"location"`
	Name     string `json:"name" yaml:"name"`
	ID       string `json:"id" yaml:"id"`
}

func (m *DeploymentErrorGet) Valid() error {
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

type DeploymentErrorGetResult struct {
	Issue DeploymentErrorIssueDetail `json:"issue" yaml:"issue"`
}

func (m *DeploymentErrorGetResult) Table() [][]string {
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

// DeploymentErrorIssueDetail is the full view: the summary plus a representative
// stack trace and recent occurrence pointers that deep-link into LogsHistory.
type DeploymentErrorIssueDetail struct {
	DeploymentErrorIssue
	// SampleMessage is the representative reassembled stack trace.
	SampleMessage string `json:"sampleMessage" yaml:"sampleMessage"`
	// RecentEvents are the most recent occurrence pointers (bounded), newest-first.
	RecentEvents []DeploymentErrorOccurrence `json:"recentEvents" yaml:"recentEvents"`
}

// DeploymentErrorOccurrence locates a single occurrence of an issue in the
// durable log store, so a viewer can jump to the surrounding logs.
type DeploymentErrorOccurrence struct {
	Pod       string    `json:"pod" yaml:"pod"`
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`
	// Object + Offset address the source line in object storage (the error-event
	// object key and the line index within it).
	Object string `json:"object" yaml:"object"`
	Offset int    `json:"offset" yaml:"offset"`
}

// DeploymentErrorUpdate changes an error issue's triage status.
type DeploymentErrorUpdate struct {
	Project  string `json:"project" yaml:"project"`
	Location string `json:"location" yaml:"location"`
	Name     string `json:"name" yaml:"name"`
	ID       string `json:"id" yaml:"id"`
	// Status is the new triage status: "resolved", "open" (reopen), or "muted".
	Status string `json:"status" yaml:"status"`
}

func (m *DeploymentErrorUpdate) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	m.ID = strings.TrimSpace(m.ID)
	m.Status = strings.TrimSpace(m.Status)

	v := validator.New()

	v.Must(m.Location != "", "location required")
	v.Must(ReValidName.MatchString(m.Name), "name invalid "+ReValidNameStr)
	v.Mustf(utf8.RuneCountInString(m.Name) <= DeploymentMaxNameLength*2, "name must have length less then %d characters", DeploymentMaxNameLength*2)
	v.Must(m.Project != "", "project required")
	v.Must(m.ID != "", "id required")
	v.Must(validDeploymentErrorStatus(m.Status), "status must be resolved, open, or muted")

	return WrapValidate(v)
}

// DeploymentErrorEvent is the capture→apiserver wire contract: one structured
// error, parsed by the capture-side reassembler from the live log stream and
// written to the per-deployment error-event object stream. apiserver reads these
// to compute the fingerprint and aggregate into issues. Versioned like the
// log-line contract; keep in sync with the log-capture writer.
type DeploymentErrorEvent struct {
	Deployment string                 `json:"deployment"`
	Pod        string                 `json:"pod"`
	Timestamp  time.Time              `json:"ts"`
	Kind       string                 `json:"kind"`   // see DeploymentErrorKind*
	Type       string                 `json:"type"`   // exception/panic class, no dynamic message
	Title      string                 `json:"title"`  // type + first message line, display-only
	Frames     []DeploymentErrorFrame `json:"frames"` // innermost-first; the fingerprint basis
	Sample     string                 `json:"sample"` // full reassembled trace, capped
}

// DeploymentErrorFrame is one parsed stack frame in a DeploymentErrorEvent.
type DeploymentErrorFrame struct {
	Func string `json:"func"`
	File string `json:"file"`
	Line int    `json:"line"`
}

func validDeploymentErrorStatus(s string) bool {
	switch s {
	case DeploymentErrorStatusOpen, DeploymentErrorStatusResolved, DeploymentErrorStatusMuted:
		return true
	}
	return false
}

func validDeploymentErrorListStatus(s string) bool {
	return s == "" || s == DeploymentErrorStatusAll || validDeploymentErrorStatus(s)
}

func validDeploymentErrorSort(s string) bool {
	switch s {
	case "", DeploymentErrorSortLastSeen, DeploymentErrorSortFirstSeen, DeploymentErrorSortCount:
		return true
	}
	return false
}
