package api

import (
	"cmp"
	"context"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/moonrhythm/validator"
)

// Alert manages a project's metric alert rules: "when deployment CPU >= 90% for
// 10 minutes, notify." A rule is a single condition on one metric of one
// deployment; the target carries the location (like Notification carries its
// delivery config), so a rule is addressed by (project, name) like an env group
// or a scheduler job — location-less at the resource level, location-bound only
// inside Target.
//
// Rules are evaluated by an apiserver cron tick (outside this package) against
// the existing per-minute deployment_usages table; there is no separate metrics
// backend for v1. Evaluation is stateless per tick over a rolling window of the
// last Condition.ForMinutes buckets, and produces one of three states: "ok"
// (condition not met), "firing" (condition held for the full window), or
// "nodata" (too few buckets present — deployment paused/deleted, or no limit
// set for a percent metric). State transitions (ok/nodata -> firing, firing ->
// ok) enqueue "alert.trigger"/"alert.resolve" notification events (see
// Notification); a still-firing rule re-notifies every RenotifyMinutes when
// set. Notification delivery reuses the notification-channels feature
// entirely — a rule carries no delivery config of its own.
//
// Rule config changes (Create/Update/Delete) go through the normal audit/change
// path like every other resource, so a channel subscribed to "alert.*" also
// sees config edits alongside trigger/resolve events. The trigger/resolve
// transitions themselves are evaluator telemetry, not user actions, and are not
// audited (mirrors deployment.health).
//
// Existence of Target.Deployment is checked at Create/Update time but a rule is
// not FK-bound to it: deleting and recreating the deployment keeps the rule,
// which simply reports "nodata" while the deployment is gone (matches how
// routes behave).
type Alert interface {
	// Create requires the `alert.create` permission.
	Create(ctx context.Context, m *AlertCreate) (*Empty, error)
	// Update requires the `alert.update` permission.
	Update(ctx context.Context, m *AlertUpdate) (*Empty, error)
	// Get requires the `alert.get` permission.
	Get(ctx context.Context, m *AlertGet) (*AlertItem, error)
	// List requires the `alert.list` permission.
	List(ctx context.Context, m *AlertList) (*AlertListResult, error)
	// Delete requires the `alert.delete` permission.
	Delete(ctx context.Context, m *AlertDelete) (*Empty, error)
	// Events lists a rule's recent state transitions, newest first — the
	// history feed for the alert detail page. Requires the `alert.get`
	// permission.
	Events(ctx context.Context, m *AlertEvents) (*AlertEventsResult, error)
}

// AlertTarget identifies what a rule watches. Location is required in v1
// (kind=deployment is implicit; Phase 2 adds a Kind field for custom-metric
// targets, which is why Condition/Target are kept flat and additive rather than
// nested further).
type AlertTarget struct {
	Location   string `json:"location" yaml:"location"`
	Deployment string `json:"deployment" yaml:"deployment"`
}

// AlertCondition is the single metric condition a rule evaluates. Op defaults
// to ">=" when left empty. Threshold's unit depends on Metric (see
// AlertMetrics): percent 0-100 for cpu/memory (usage as a share of the
// deployment's limit, allowed above 100% since limits can be briefly
// overcommitted), req/min for requests, or bytes/min for egress. ForMinutes is
// how long the condition must hold continuously, evaluated as a rolling
// window (1..60 minutes).
type AlertCondition struct {
	Metric     string  `json:"metric" yaml:"metric"`
	Op         string  `json:"op" yaml:"op"` // ">=" or "<="; default ">=" on empty
	Threshold  float64 `json:"threshold" yaml:"threshold"`
	ForMinutes int     `json:"forMinutes" yaml:"forMinutes"`
}

// Metric vocabulary (v1). See the SPEC for the backing deployment_usages series
// and bucket aggregation each metric uses.
const (
	AlertMetricCPU      = "cpu"      // % of limit, avg across pods
	AlertMetricMemory   = "memory"   // % of limit, avg across pods
	AlertMetricRequests = "requests" // req/min, summed across pods
	AlertMetricEgress   = "egress"   // bytes/min, summed across pods
)

var alertMetrics = []string{
	AlertMetricCPU,
	AlertMetricMemory,
	AlertMetricRequests,
	AlertMetricEgress,
}

// AlertMetrics returns the v1 metric vocabulary a Condition.Metric may target —
// the discovery list for a rule-creation UI (mirrors NotificationEvents). The
// returned slice is a copy.
func AlertMetrics() []string {
	return slices.Clone(alertMetrics)
}

func alertMetricIsPercent(metric string) bool {
	return metric == AlertMetricCPU || metric == AlertMetricMemory
}

// Comparison operators a condition may use.
const (
	AlertOpGTE = ">="
	AlertOpLTE = "<="
)

// Evaluator states (AlertItem.Status). See the Alert doc comment for the
// breach/nodata/ok decision and the state-machine transitions.
const (
	AlertStatusOK     = "ok"
	AlertStatusFiring = "firing"
	AlertStatusNoData = "nodata"
)

// Event transitions recorded per tick and carried on AlertEvent.Transition.
const (
	AlertTransitionTrigger  = "trigger"  // ok/nodata -> firing
	AlertTransitionResolve  = "resolve"  // firing -> ok
	AlertTransitionRenotify = "renotify" // firing -> firing, RenotifyMinutes elapsed
)

// validAlertName mirrors the env-group/scheduler/notification name rules
// (DNS-label friendly).
func validAlertName(v *validator.Validator, name string) {
	v.Must(ReValidName.MatchString(name), "name invalid: "+ReValidNameDesc)
	cnt := utf8.RuneCountInString(name)
	v.Mustf(cnt >= MinNameLength && cnt <= MaxNameLength, "name must have length between %d-%d characters", MinNameLength, MaxNameLength)
}

// validAlertTarget checks Target's shape only; whether Location/Deployment
// actually resolve to an existing deployment is a server-side lookup (see the
// Alert doc comment), not client-side validation.
func validAlertTarget(v *validator.Validator, t AlertTarget) {
	v.Must(t.Location != "", "target.location required")
	v.Must(ReValidName.MatchString(t.Deployment), "target.deployment invalid: "+ReValidNameDesc)
	cnt := utf8.RuneCountInString(t.Deployment)
	v.Mustf(cnt >= MinNameLength && cnt <= DeploymentMaxNameLength, "target.deployment must have length between %d-%d characters", MinNameLength, DeploymentMaxNameLength)
}

func validAlertCondition(v *validator.Validator, c AlertCondition) {
	v.Must(slices.Contains(alertMetrics, c.Metric), "condition.metric invalid (want cpu, memory, requests, or egress)")
	v.Must(c.Op == AlertOpGTE || c.Op == AlertOpLTE, "condition.op invalid (want >= or <=)")
	v.Must(c.Threshold > 0, "condition.threshold must be greater than 0")
	v.Must(!math.IsInf(c.Threshold, 0), "condition.threshold must be finite")
	if alertMetricIsPercent(c.Metric) {
		v.Mustf(c.Threshold <= AlertPercentThresholdMax, "condition.threshold must not exceed %v for percent metrics", AlertPercentThresholdMax)
	}
	v.Mustf(c.ForMinutes >= AlertForMinutesMin && c.ForMinutes <= AlertForMinutesMax, "condition.forMinutes must be between %d and %d", AlertForMinutesMin, AlertForMinutesMax)
}

// validAlertRenotifyMinutes: 0 disables re-notification (transitions only);
// anything else must fall within the bounds.
func validAlertRenotifyMinutes(v *validator.Validator, m int) {
	if m == 0 {
		return
	}
	v.Mustf(m >= AlertRenotifyMinutesMin && m <= AlertRenotifyMinutesMax, "renotifyMinutes must be 0 (disabled) or between %d and %d", AlertRenotifyMinutesMin, AlertRenotifyMinutesMax)
}

type AlertCreate struct {
	Project         string         `json:"project" yaml:"project"`
	Name            string         `json:"name" yaml:"name"`
	Target          AlertTarget    `json:"target" yaml:"target"`
	Condition       AlertCondition `json:"condition" yaml:"condition"`
	RenotifyMinutes int            `json:"renotifyMinutes" yaml:"renotifyMinutes"`
	Disabled        bool           `json:"disabled" yaml:"disabled"`
}

func (m *AlertCreate) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	m.Target.Location = strings.TrimSpace(m.Target.Location)
	m.Target.Deployment = strings.TrimSpace(m.Target.Deployment)
	m.Condition.Metric = strings.TrimSpace(m.Condition.Metric)
	m.Condition.Op = cmp.Or(strings.TrimSpace(m.Condition.Op), AlertOpGTE)

	v := validator.New()
	v.Must(m.Project != "", "project required")
	validAlertName(v, m.Name)
	validAlertTarget(v, m.Target)
	validAlertCondition(v, m.Condition)
	validAlertRenotifyMinutes(v, m.RenotifyMinutes)

	return WrapValidate(v)
}

// AlertUpdate replaces a rule's whole configuration (a full upsert, like
// SchedulerUpdate) — Target, Condition, RenotifyMinutes, and Disabled are all
// replaced wholesale. Name identifies the rule and is immutable; there is no
// rename.
type AlertUpdate struct {
	Project         string         `json:"project" yaml:"project"`
	Name            string         `json:"name" yaml:"name"`
	Target          AlertTarget    `json:"target" yaml:"target"`
	Condition       AlertCondition `json:"condition" yaml:"condition"`
	RenotifyMinutes int            `json:"renotifyMinutes" yaml:"renotifyMinutes"`
	Disabled        bool           `json:"disabled" yaml:"disabled"`
}

func (m *AlertUpdate) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	m.Target.Location = strings.TrimSpace(m.Target.Location)
	m.Target.Deployment = strings.TrimSpace(m.Target.Deployment)
	m.Condition.Metric = strings.TrimSpace(m.Condition.Metric)
	m.Condition.Op = cmp.Or(strings.TrimSpace(m.Condition.Op), AlertOpGTE)

	v := validator.New()
	v.Must(m.Project != "", "project required")
	validAlertName(v, m.Name)
	validAlertTarget(v, m.Target)
	validAlertCondition(v, m.Condition)
	validAlertRenotifyMinutes(v, m.RenotifyMinutes)

	return WrapValidate(v)
}

type AlertGet struct {
	Project string `json:"project" yaml:"project"`
	Name    string `json:"name" yaml:"name"`
}

func (m *AlertGet) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	v := validator.New()
	v.Must(m.Project != "", "project required")
	validAlertName(v, m.Name)
	return WrapValidate(v)
}

type AlertDelete struct {
	Project string `json:"project" yaml:"project"`
	Name    string `json:"name" yaml:"name"`
}

func (m *AlertDelete) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	v := validator.New()
	v.Must(m.Project != "", "project required")
	validAlertName(v, m.Name)
	return WrapValidate(v)
}

type AlertList struct {
	Project string `json:"project" yaml:"project"`
}

func (m *AlertList) Valid() error {
	v := validator.New()
	v.Must(m.Project != "", "project required")
	return WrapValidate(v)
}

// AlertEvents lists a rule's recent state transitions, newest first (see
// AlertEventsResult).
type AlertEvents struct {
	Project string `json:"project" yaml:"project"`
	Name    string `json:"name" yaml:"name"`
	Limit   int    `json:"limit" yaml:"limit"`
}

func (m *AlertEvents) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	v := validator.New()
	v.Must(m.Project != "", "project required")
	validAlertName(v, m.Name)
	if err := WrapValidate(v); err != nil {
		return err
	}
	if m.Limit <= 0 {
		m.Limit = AlertEventsDefaultLimit
	}
	m.Limit = min(m.Limit, AlertEventsMaxLimit)
	return nil
}

// AlertItem is the read view of a rule, including the evaluator's read-only
// state (Status/LastValue/FiringSince/LastEvaluatedAt), set by the alert-tick
// cron and ignored on write.
type AlertItem struct {
	Project         string         `json:"project" yaml:"project"`
	Name            string         `json:"name" yaml:"name"`
	Target          AlertTarget    `json:"target" yaml:"target"`
	Condition       AlertCondition `json:"condition" yaml:"condition"`
	RenotifyMinutes int            `json:"renotifyMinutes" yaml:"renotifyMinutes"`
	Disabled        bool           `json:"disabled" yaml:"disabled"`
	// read-only evaluator state
	Status          string     `json:"status" yaml:"status"` // ok|firing|nodata
	LastValue       *float64   `json:"lastValue" yaml:"lastValue"`
	FiringSince     *time.Time `json:"firingSince" yaml:"firingSince"`
	LastEvaluatedAt *time.Time `json:"lastEvaluatedAt" yaml:"lastEvaluatedAt"`
	CreatedAt       time.Time  `json:"createdAt" yaml:"createdAt"`
	CreatedBy       string     `json:"createdBy" yaml:"createdBy"`
	UpdatedAt       time.Time  `json:"updatedAt" yaml:"updatedAt"`
	UpdatedBy       string     `json:"updatedBy" yaml:"updatedBy"`
}

func alertTargetString(t AlertTarget) string {
	return t.Location + "/" + t.Deployment
}

func alertConditionString(c AlertCondition) string {
	return c.Metric + " " + c.Op + " " + strconv.FormatFloat(c.Threshold, 'f', -1, 64) + " for " + strconv.Itoa(c.ForMinutes) + "m"
}

func alertValueString(v *float64) string {
	if v == nil {
		return "-"
	}
	return strconv.FormatFloat(*v, 'f', 2, 64)
}

func alertStatus(x *AlertItem) string {
	if x.Disabled {
		return "disabled"
	}
	if x.Status == "" {
		return "-"
	}
	return x.Status
}

func alertRow(x *AlertItem) []string {
	return []string{
		x.Name,
		alertTargetString(x.Target),
		alertConditionString(x.Condition),
		alertStatus(x),
		alertValueString(x.LastValue),
		age(x.CreatedAt),
	}
}

func (m *AlertItem) Table() [][]string {
	return [][]string{
		{"NAME", "TARGET", "CONDITION", "STATUS", "LAST VALUE", "AGE"},
		alertRow(m),
	}
}

type AlertListResult struct {
	Project string       `json:"project" yaml:"project"`
	Items   []*AlertItem `json:"items" yaml:"items"`
}

func (m *AlertListResult) Table() [][]string {
	table := [][]string{
		{"NAME", "TARGET", "CONDITION", "STATUS", "LAST VALUE", "AGE"},
	}
	for _, x := range m.Items {
		table = append(table, alertRow(x))
	}
	return table
}

// AlertEvent is one recorded state transition (see the alert_events table in
// the evaluator schema).
type AlertEvent struct {
	At         time.Time `json:"at" yaml:"at"`
	Transition string    `json:"transition" yaml:"transition"` // trigger|resolve|renotify
	Value      *float64  `json:"value" yaml:"value"`
}

func alertEventRow(x *AlertEvent) []string {
	return []string{
		age(x.At),
		x.Transition,
		alertValueString(x.Value),
	}
}

// AlertEventsResult is a rule's recent state transitions, newest first — the
// history feed for the alert detail page.
type AlertEventsResult struct {
	Project string        `json:"project" yaml:"project"`
	Name    string        `json:"name" yaml:"name"`
	Items   []*AlertEvent `json:"items" yaml:"items"`
}

func (m *AlertEventsResult) Table() [][]string {
	table := [][]string{
		{"TIME", "TRANSITION", "VALUE"},
	}
	for _, x := range m.Items {
		table = append(table, alertEventRow(x))
	}
	return table
}
