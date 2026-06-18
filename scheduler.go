package api

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/moonrhythm/validator"
)

// Scheduler manages a project's scheduled HTTP requests: cron-driven jobs that
// fire a fully-customizable outbound HTTP request (method, url, headers, auth,
// body) on a schedule. Jobs are project-scoped and location-less — the engine
// runs inside apiserver (a Cloud-Scheduler-driven /_internal tick claims due
// jobs and fires them exactly once across replicas), not tied to any deploy
// location, so a job is addressed by (project, name) like an env group.
//
// Every run is recorded as an invocation (timestamp, pending/success/failed,
// latency, http status, error) readable via Logs, and the job carries the
// denormalized last-run result so a list view can show the last status without a
// per-row subquery. Jobs can be paused/resumed and triggered manually; a manual
// trigger records a pending invocation and runs it asynchronously (it does not
// block on the request completing).
//
// Outbound requests send a default User-Agent (SchedulerDefaultUserAgent) so the
// platform WAF can allowlist them; a job may override it via a custom
// "User-Agent" header. InsecureSkipVerify disables TLS verification for HTTPS
// targets (self-signed certs); the server still blocks private/link-local/
// metadata targets to avoid SSRF.
type Scheduler interface {
	// Create requires the `scheduler.create` permission.
	Create(ctx context.Context, m *SchedulerCreate) (*Empty, error)
	// Update requires the `scheduler.update` permission.
	Update(ctx context.Context, m *SchedulerUpdate) (*Empty, error)
	// Get requires the `scheduler.get` permission.
	Get(ctx context.Context, m *SchedulerGet) (*SchedulerItem, error)
	// List requires the `scheduler.list` permission.
	List(ctx context.Context, m *SchedulerList) (*SchedulerListResult, error)
	// Delete requires the `scheduler.delete` permission.
	Delete(ctx context.Context, m *SchedulerDelete) (*Empty, error)
	// Pause requires the `scheduler.update` permission.
	Pause(ctx context.Context, m *SchedulerPause) (*Empty, error)
	// Resume requires the `scheduler.update` permission.
	Resume(ctx context.Context, m *SchedulerResume) (*Empty, error)
	// Trigger enqueues a one-off run and returns immediately with the newly
	// recorded pending invocation; the run completes asynchronously and the
	// invocation (poll via Logs) resolves to success or failed. It runs even when
	// the job is paused and does not change the cron schedule. Requires the
	// `scheduler.run` permission.
	Trigger(ctx context.Context, m *SchedulerTrigger) (*SchedulerInvocation, error)
	// Logs lists a job's recent invocations, newest first. Requires the
	// `scheduler.get` permission.
	Logs(ctx context.Context, m *SchedulerLogs) (*SchedulerLogsResult, error)
}

// SchedulerAuth configures optional HTTP authentication added to every scheduled
// request.
//
// Secret is WRITE-ONLY: it is accepted on Create/Update but never returned by
// Get/List (responses echo Type and Username only). On Update, leave Secret
// empty to keep the previously stored secret; send a new value to replace it.
type SchedulerAuth struct {
	// Type is "none" (default), "basic" (Username+Secret sent as HTTP Basic), or
	// "bearer" (Secret sent as an "Authorization: Bearer <secret>" header).
	Type string `json:"type" yaml:"type"`
	// Username is the Basic-auth username (type=basic only).
	Username string `json:"username" yaml:"username"`
	// Secret is the Basic-auth password or the Bearer token. Write-only: it is
	// never populated in Get/List responses.
	Secret string `json:"secret,omitempty" yaml:"secret,omitempty"`
}

const (
	SchedulerAuthNone   = "none"
	SchedulerAuthBasic  = "basic"
	SchedulerAuthBearer = "bearer"
)

var validSchedulerAuthTypes = map[string]bool{
	"":                  true, // treated as none
	SchedulerAuthNone:   true,
	SchedulerAuthBasic:  true,
	SchedulerAuthBearer: true,
}

var validSchedulerMethods = map[string]bool{
	"GET":     true,
	"POST":    true,
	"PUT":     true,
	"PATCH":   true,
	"DELETE":  true,
	"HEAD":    true,
	"OPTIONS": true,
}

// validSchedulerName mirrors the env-group name rules (DNS-label friendly).
func validSchedulerName(v *validator.Validator, name string) {
	v.Must(ReValidName.MatchString(name), "name invalid "+ReValidNameStr)
	cnt := utf8.RuneCountInString(name)
	v.Mustf(cnt >= MinNameLength && cnt <= MaxNameLength, "name must have length between %d-%d characters", MinNameLength, MaxNameLength)
}

// validSchedulerSchedule accepts the same 5-field cron syntax the platform
// already uses for cronjob deployments (ReValidSchedule) plus the common
// descriptor macros (@hourly, @daily, …) and "@every <duration>". The server
// re-parses authoritatively (robfig/cron) and returns ErrScheduleInvalid.
func validSchedulerSchedule(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	switch s {
	case "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly":
		return true
	}
	if rest, ok := strings.CutPrefix(s, "@every "); ok {
		d, err := time.ParseDuration(strings.TrimSpace(rest))
		return err == nil && d >= time.Minute
	}
	return ReValidSchedule.MatchString(s)
}

func validSchedulerHeaders(v *validator.Validator, headers map[string]string) {
	v.Mustf(len(headers) <= SchedulerMaxHeaders, "headers must not exceed %d entries", SchedulerMaxHeaders)
	for k, val := range headers {
		v.Mustf(k != "" && utf8.RuneCountInString(k) <= SchedulerMaxHeaderKeyLength, "header name invalid")
		v.Mustf(!strings.ContainsAny(k, " :\r\n\t"), "header name %q invalid", k)
		v.Mustf(!strings.ContainsAny(val, "\r\n"), "header %q value invalid", k)
		v.Mustf(utf8.RuneCountInString(val) <= SchedulerMaxHeaderValueLength, "header %q value too long", k)
	}
}

func validSchedulerURL(v *validator.Validator, raw string) {
	v.Must(raw != "", "url required")
	v.Mustf(utf8.RuneCountInString(raw) <= SchedulerMaxURLLength, "url must not exceed %d characters", SchedulerMaxURLLength)
	if raw == "" {
		return
	}
	u, err := url.Parse(raw)
	if err != nil {
		v.Must(false, "url invalid")
		return
	}
	v.Must(u.Scheme == "http" || u.Scheme == "https", "url must be http or https")
	v.Must(u.Host != "", "url host required")
}

// validSchedulerAuth validates the auth block. requireSecret is true for Create
// (a basic/bearer auth must carry its secret) and false for Update (an empty
// secret means "keep the stored one").
func validSchedulerAuth(v *validator.Validator, a SchedulerAuth, requireSecret bool) {
	v.Must(validSchedulerAuthTypes[a.Type], "auth type invalid (want none|basic|bearer)")
	switch a.Type {
	case SchedulerAuthBasic:
		v.Must(a.Username != "", "auth username required for basic auth")
		if requireSecret {
			v.Must(a.Secret != "", "auth secret required for basic auth")
		}
	case SchedulerAuthBearer:
		if requireSecret {
			v.Must(a.Secret != "", "auth secret required for bearer auth")
		}
	}
	v.Mustf(utf8.RuneCountInString(a.Username) <= SchedulerMaxHeaderValueLength, "auth username too long")
	v.Mustf(utf8.RuneCountInString(a.Secret) <= SchedulerMaxHeaderValueLength, "auth secret too long")
}

func validSchedulerRequestShape(v *validator.Validator, method, rawURL, body string, headers map[string]string, schedule, timezone string, auth SchedulerAuth, requireSecret bool) {
	v.Must(validSchedulerMethods[strings.ToUpper(method)], "method invalid")
	validSchedulerURL(v, rawURL)
	validSchedulerHeaders(v, headers)
	v.Mustf(len(body) <= SchedulerMaxBodySize, "body must not exceed %d bytes", SchedulerMaxBodySize)
	v.Must(validSchedulerSchedule(schedule), "schedule invalid")
	v.Mustf(utf8.RuneCountInString(timezone) <= 64, "timezone invalid")
	validSchedulerAuth(v, auth, requireSecret)
}

type SchedulerCreate struct {
	Project            string            `json:"project" yaml:"project"`
	Name               string            `json:"name" yaml:"name"`
	Schedule           string            `json:"schedule" yaml:"schedule"`
	Timezone           string            `json:"timezone" yaml:"timezone"` // IANA tz, default UTC
	Method             string            `json:"method" yaml:"method"`
	URL                string            `json:"url" yaml:"url"`
	Headers            map[string]string `json:"headers" yaml:"headers"`
	Body               string            `json:"body" yaml:"body"`
	Auth               SchedulerAuth     `json:"auth" yaml:"auth"`
	InsecureSkipVerify bool              `json:"insecureSkipVerify" yaml:"insecureSkipVerify"`
	Paused             bool              `json:"paused" yaml:"paused"`
}

func (m *SchedulerCreate) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	m.Schedule = strings.TrimSpace(m.Schedule)
	m.Timezone = strings.TrimSpace(m.Timezone)
	m.Method = strings.ToUpper(strings.TrimSpace(m.Method))
	if m.Method == "" {
		m.Method = "GET"
	}
	m.URL = strings.TrimSpace(m.URL)
	m.Auth.Type = strings.TrimSpace(m.Auth.Type)

	v := validator.New()
	v.Must(m.Project != "", "project required")
	validSchedulerName(v, m.Name)
	validSchedulerRequestShape(v, m.Method, m.URL, m.Body, m.Headers, m.Schedule, m.Timezone, m.Auth, true)

	return WrapValidate(v)
}

// SchedulerUpdate replaces the whole job configuration (it is a full upsert of
// the request shape, like cache.set). Leave Auth.Secret empty to keep the
// stored secret; set it to replace it.
type SchedulerUpdate struct {
	Project            string            `json:"project" yaml:"project"`
	Name               string            `json:"name" yaml:"name"`
	Schedule           string            `json:"schedule" yaml:"schedule"`
	Timezone           string            `json:"timezone" yaml:"timezone"`
	Method             string            `json:"method" yaml:"method"`
	URL                string            `json:"url" yaml:"url"`
	Headers            map[string]string `json:"headers" yaml:"headers"`
	Body               string            `json:"body" yaml:"body"`
	Auth               SchedulerAuth     `json:"auth" yaml:"auth"`
	InsecureSkipVerify bool              `json:"insecureSkipVerify" yaml:"insecureSkipVerify"`
}

func (m *SchedulerUpdate) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	m.Schedule = strings.TrimSpace(m.Schedule)
	m.Timezone = strings.TrimSpace(m.Timezone)
	m.Method = strings.ToUpper(strings.TrimSpace(m.Method))
	if m.Method == "" {
		m.Method = "GET"
	}
	m.URL = strings.TrimSpace(m.URL)
	m.Auth.Type = strings.TrimSpace(m.Auth.Type)

	v := validator.New()
	v.Must(m.Project != "", "project required")
	validSchedulerName(v, m.Name)
	validSchedulerRequestShape(v, m.Method, m.URL, m.Body, m.Headers, m.Schedule, m.Timezone, m.Auth, false)

	return WrapValidate(v)
}

type SchedulerGet struct {
	Project string `json:"project" yaml:"project"`
	Name    string `json:"name" yaml:"name"`
}

func (m *SchedulerGet) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	v := validator.New()
	v.Must(m.Project != "", "project required")
	validSchedulerName(v, m.Name)
	return WrapValidate(v)
}

type SchedulerDelete struct {
	Project string `json:"project" yaml:"project"`
	Name    string `json:"name" yaml:"name"`
}

func (m *SchedulerDelete) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	v := validator.New()
	v.Must(m.Project != "", "project required")
	validSchedulerName(v, m.Name)
	return WrapValidate(v)
}

type SchedulerPause struct {
	Project string `json:"project" yaml:"project"`
	Name    string `json:"name" yaml:"name"`
}

func (m *SchedulerPause) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	v := validator.New()
	v.Must(m.Project != "", "project required")
	validSchedulerName(v, m.Name)
	return WrapValidate(v)
}

type SchedulerResume struct {
	Project string `json:"project" yaml:"project"`
	Name    string `json:"name" yaml:"name"`
}

func (m *SchedulerResume) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	v := validator.New()
	v.Must(m.Project != "", "project required")
	validSchedulerName(v, m.Name)
	return WrapValidate(v)
}

type SchedulerTrigger struct {
	Project string `json:"project" yaml:"project"`
	Name    string `json:"name" yaml:"name"`
}

func (m *SchedulerTrigger) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	v := validator.New()
	v.Must(m.Project != "", "project required")
	validSchedulerName(v, m.Name)
	return WrapValidate(v)
}

type SchedulerList struct {
	Project string `json:"project" yaml:"project"`
}

func (m *SchedulerList) Valid() error {
	v := validator.New()
	v.Must(m.Project != "", "project required")
	return WrapValidate(v)
}

type SchedulerLogs struct {
	Project string    `json:"project" yaml:"project"`
	Name    string    `json:"name" yaml:"name"`
	After   time.Time `json:"after" yaml:"after"`
	Before  time.Time `json:"before" yaml:"before"`
	Limit   int       `json:"limit" yaml:"limit"`
}

func (m *SchedulerLogs) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	v := validator.New()
	v.Must(m.Project != "", "project required")
	validSchedulerName(v, m.Name)
	if err := WrapValidate(v); err != nil {
		return err
	}
	if m.Limit <= 0 {
		m.Limit = SchedulerDefaultLogLimit
	}
	if m.Limit > SchedulerMaxLogLimit {
		m.Limit = SchedulerMaxLogLimit
	}
	return nil
}

// SchedulerItem is the read view of a job. Auth.Secret is always empty here.
type SchedulerItem struct {
	Project            string            `json:"project" yaml:"project"`
	Name               string            `json:"name" yaml:"name"`
	Schedule           string            `json:"schedule" yaml:"schedule"`
	Timezone           string            `json:"timezone" yaml:"timezone"`
	Method             string            `json:"method" yaml:"method"`
	URL                string            `json:"url" yaml:"url"`
	Headers            map[string]string `json:"headers" yaml:"headers"`
	Body               string            `json:"body" yaml:"body"`
	Auth               SchedulerAuth     `json:"auth" yaml:"auth"`
	InsecureSkipVerify bool              `json:"insecureSkipVerify" yaml:"insecureSkipVerify"`
	Paused             bool              `json:"paused" yaml:"paused"`
	// Denormalized last-run state (drives the list "last status" column).
	// LastResult is "" before the first run, then "success" or "failed".
	LastResult     string     `json:"lastResult" yaml:"lastResult"`
	LastRunAt      *time.Time `json:"lastRunAt" yaml:"lastRunAt"`
	LastLatencyMs  int        `json:"lastLatencyMs" yaml:"lastLatencyMs"`
	LastHTTPStatus int        `json:"lastHttpStatus" yaml:"lastHttpStatus"`
	LastError      string     `json:"lastError" yaml:"lastError"`
	NextRunAt      *time.Time `json:"nextRunAt" yaml:"nextRunAt"`
	CreatedAt      time.Time  `json:"createdAt" yaml:"createdAt"`
	CreatedBy      string     `json:"createdBy" yaml:"createdBy"`
	UpdatedAt      time.Time  `json:"updatedAt" yaml:"updatedAt"`
	UpdatedBy      string     `json:"updatedBy" yaml:"updatedBy"`
}

func schedulerLastStatus(result string, paused bool) string {
	if paused {
		return "paused"
	}
	if result == "" {
		return "-"
	}
	return result
}

func (m *SchedulerItem) Table() [][]string {
	return [][]string{
		{"NAME", "SCHEDULE", "METHOD", "STATUS", "AGE"},
		{
			m.Name,
			m.Schedule,
			m.Method,
			schedulerLastStatus(m.LastResult, m.Paused),
			age(m.CreatedAt),
		},
	}
}

type SchedulerListResult struct {
	Project string           `json:"project" yaml:"project"`
	Items   []*SchedulerItem `json:"items" yaml:"items"`
}

func (m *SchedulerListResult) Table() [][]string {
	table := [][]string{
		{"NAME", "SCHEDULE", "METHOD", "STATUS", "AGE"},
	}
	for _, x := range m.Items {
		table = append(table, []string{
			x.Name,
			x.Schedule,
			x.Method,
			schedulerLastStatus(x.LastResult, x.Paused),
			age(x.CreatedAt),
		})
	}
	return table
}

// Invocation result states. A manually-triggered run is recorded as
// SchedulerResultPending and runs asynchronously, resolving to
// SchedulerResultSuccess (2xx response) or SchedulerResultFailed; cron-driven
// runs are recorded directly as success/failed.
const (
	SchedulerResultPending = "pending"
	SchedulerResultSuccess = "success"
	SchedulerResultFailed  = "failed"
)

// SchedulerInvocation is one recorded run. HTTPStatus is 0 when no response was
// received (connection refused, DNS failure, timeout, blocked target) or while
// the run is still pending; Error holds the reason. Result is "pending" (a
// manual trigger whose run has not finished), "success" (2xx response), or
// "failed".
type SchedulerInvocation struct {
	ID         string    `json:"id" yaml:"id"`
	StartedAt  time.Time `json:"startedAt" yaml:"startedAt"`
	Result     string    `json:"result" yaml:"result"`
	HTTPStatus int       `json:"httpStatus" yaml:"httpStatus"`
	LatencyMs  int       `json:"latencyMs" yaml:"latencyMs"`
	Error      string    `json:"error" yaml:"error"`
}

func (m *SchedulerInvocation) Table() [][]string {
	return [][]string{
		{"TIME", "RESULT", "STATUS", "LATENCY", "ERROR"},
		schedulerInvocationRow(m),
	}
}

type SchedulerLogsResult struct {
	Project string                 `json:"project" yaml:"project"`
	Name    string                 `json:"name" yaml:"name"`
	Items   []*SchedulerInvocation `json:"items" yaml:"items"`
}

func (m *SchedulerLogsResult) Table() [][]string {
	table := [][]string{
		{"TIME", "RESULT", "STATUS", "LATENCY", "ERROR"},
	}
	for _, x := range m.Items {
		table = append(table, schedulerInvocationRow(x))
	}
	return table
}

func schedulerInvocationRow(x *SchedulerInvocation) []string {
	status := ""
	if x.HTTPStatus > 0 {
		status = strconv.Itoa(x.HTTPStatus)
	}
	return []string{
		age(x.StartedAt),
		x.Result,
		status,
		strconv.Itoa(x.LatencyMs) + "ms",
		x.Error,
	}
}
