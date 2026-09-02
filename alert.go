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
// target — either a platform deployment metric (kind=deployment, the default
// when Kind is empty) or a custom metric-source series (kind=custom). The
// resource is addressed by (project, name) like an env group or a scheduler
// job — location-less at the resource level. For kind=deployment, location
// lives on Target; for kind=custom, location lives on the metric source.
//
// Rules are evaluated by an apiserver cron tick (outside this package) against
// the existing per-minute deployment_usages table (kind=deployment) or
// custom_usages (kind=custom). Evaluation is stateless per tick over a rolling
// window of the last Condition.ForMinutes buckets, and produces one of three
// states: "ok" (condition not met), "firing" (condition held for the full
// window), or "nodata" (too few buckets present — deployment paused/deleted,
// source gone, or no limit set for a percent metric). State transitions
// (ok/nodata -> firing, firing -> ok) enqueue "alert.trigger"/"alert.resolve"
// notification events (see Notification); a still-firing rule re-notifies
// every RenotifyMinutes when set. Notification delivery reuses the
// notification-channels feature entirely — a rule carries no delivery config
// of its own.
//
// Rule config changes (Create/Update/Delete) go through the normal audit/change
// path like every other resource, so a channel subscribed to "alert.*" also
// sees config edits alongside trigger/resolve events. The trigger/resolve
// transitions themselves are evaluator telemetry, not user actions, and are not
// audited (mirrors deployment.health).
//
// Existence of Target.Deployment (kind=deployment) or Target.Source
// (kind=custom) is checked at Create/Update time but a rule is not FK-bound
// to it: deleting the target keeps the rule, which simply reports "nodata"
// while the target is gone (matches how routes behave).
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

// AlertTarget identifies what a rule watches. Empty Kind is treated as
// deployment (clients need not send "deployment"). kind=custom targets a
// metricSource series; location lives on the source, so Location and
// Deployment must be empty.
type AlertTarget struct {
	Kind       string `json:"kind" yaml:"kind"`             // "" or "deployment" or "custom"
	Location   string `json:"location" yaml:"location"`     // kind=deployment
	Deployment string `json:"deployment" yaml:"deployment"` // kind=deployment
	Source     string `json:"source" yaml:"source"`         // kind=custom: metricSource name
	Series     string `json:"series" yaml:"series"`         // kind=custom: exact series key
}

const (
	AlertTargetKindDeployment = "deployment" // default when Kind is empty
	AlertTargetKindCustom     = "custom"
)

// AlertCondition is the single metric condition a rule evaluates. Op defaults
// to ">=" when left empty. Threshold's unit depends on Metric (see
// AlertMetrics / AlertCustomMetrics): percent 0-100 for cpu/memory (usage as
// a share of the deployment's limit, allowed above 100% since limits can be
// briefly overcommitted), req/min for requests, bytes/min for egress, the
// gauge value for kind=custom Metric=value, or per-minute increase for
// kind=custom Metric=rate. ForMinutes is how long the condition must hold
// continuously, evaluated as a rolling window (1..60 minutes).
type AlertCondition struct {
	Metric     string  `json:"metric" yaml:"metric"`
	Op         string  `json:"op" yaml:"op"` // ">=" or "<="; default ">=" on empty
	Threshold  float64 `json:"threshold" yaml:"threshold"`
	ForMinutes int     `json:"forMinutes" yaml:"forMinutes"`
}

// Platform metric vocabulary (kind=deployment). See the SPEC for the backing
// deployment_usages series and bucket aggregation each metric uses.
const (
	AlertMetricCPU      = "cpu"      // % of limit, avg across pods
	AlertMetricMemory   = "memory"   // % of limit, avg across pods
	AlertMetricRequests = "requests" // req/min, summed across pods
	AlertMetricEgress   = "egress"   // bytes/min, summed across pods
)

// Custom metric vocabulary (kind=custom).
const (
	AlertMetricValue = "value" // gauge, kind=custom
	AlertMetricRate  = "rate"  // counter per-minute, kind=custom
)

var alertMetrics = []string{
	AlertMetricCPU,
	AlertMetricMemory,
	AlertMetricRequests,
	AlertMetricEgress,
}

var alertCustomMetrics = []string{
	AlertMetricValue,
	AlertMetricRate,
}

// AlertMetrics returns the platform (kind=deployment) metric vocabulary a
// Condition.Metric may target — the discovery list for a rule-creation UI
// (mirrors NotificationEvents). The returned slice is a copy.
func AlertMetrics() []string {
	return slices.Clone(alertMetrics)
}

// AlertCustomMetrics returns the kind=custom metric vocabulary a
// Condition.Metric may target (value = gauge, rate = counter per-minute).
// The returned slice is a copy.
func AlertCustomMetrics() []string {
	return slices.Clone(alertCustomMetrics)
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

func alertTargetKind(kind string) string {
	return cmp.Or(kind, AlertTargetKindDeployment)
}

// validAlertTarget checks Target's shape only; whether Location/Deployment
// (or Source) actually resolve is a server-side lookup (see the Alert doc
// comment), not client-side validation. Empty Kind is treated as deployment
// and is not rewritten on the struct.
func validAlertTarget(v *validator.Validator, t AlertTarget) {
	switch alertTargetKind(t.Kind) {
	case AlertTargetKindDeployment:
		v.Must(t.Location != "", "target.location required")
		v.Must(ReValidName.MatchString(t.Deployment), "target.deployment invalid: "+ReValidNameDesc)
		cnt := utf8.RuneCountInString(t.Deployment)
		v.Mustf(cnt >= MinNameLength && cnt <= DeploymentMaxNameLength, "target.deployment must have length between %d-%d characters", MinNameLength, DeploymentMaxNameLength)
		v.Must(t.Source == "", "target.source is only valid for kind=custom")
		v.Must(t.Series == "", "target.series is only valid for kind=custom")
	case AlertTargetKindCustom:
		v.Must(t.Location == "", "target.location is only valid for kind=deployment")
		v.Must(t.Deployment == "", "target.deployment is only valid for kind=deployment")
		v.Must(ReValidName.MatchString(t.Source), "target.source invalid: "+ReValidNameDesc)
		cnt := utf8.RuneCountInString(t.Source)
		v.Mustf(cnt >= MinNameLength && cnt <= MaxNameLength, "target.source must have length between %d-%d characters", MinNameLength, MaxNameLength)
		v.Must(t.Series != "", "target.series required")
		v.Mustf(utf8.RuneCountInString(t.Series) <= MetricSourceMaxSeriesKey, "target.series must not exceed %d characters", MetricSourceMaxSeriesKey)
	default:
		v.Must(false, "target.kind invalid (want deployment or custom)")
	}
}

func validAlertCondition(v *validator.Validator, kind string, c AlertCondition) {
	switch alertTargetKind(kind) {
	case AlertTargetKindCustom:
		v.Must(slices.Contains(alertCustomMetrics, c.Metric), "condition.metric invalid (want value or rate)")
	default:
		v.Must(slices.Contains(alertMetrics, c.Metric), "condition.metric invalid (want cpu, memory, requests, or egress)")
	}
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
	m.Target.Kind = strings.TrimSpace(m.Target.Kind)
	m.Target.Location = strings.TrimSpace(m.Target.Location)
	m.Target.Deployment = strings.TrimSpace(m.Target.Deployment)
	m.Target.Source = strings.TrimSpace(m.Target.Source)
	m.Target.Series = strings.TrimSpace(m.Target.Series)
	m.Condition.Metric = strings.TrimSpace(m.Condition.Metric)
	m.Condition.Op = cmp.Or(strings.TrimSpace(m.Condition.Op), AlertOpGTE)

	v := validator.New()
	v.Must(m.Project != "", "project required")
	validAlertName(v, m.Name)
	validAlertTarget(v, m.Target)
	validAlertCondition(v, m.Target.Kind, m.Condition)
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
	m.Target.Kind = strings.TrimSpace(m.Target.Kind)
	m.Target.Location = strings.TrimSpace(m.Target.Location)
	m.Target.Deployment = strings.TrimSpace(m.Target.Deployment)
	m.Target.Source = strings.TrimSpace(m.Target.Source)
	m.Target.Series = strings.TrimSpace(m.Target.Series)
	m.Condition.Metric = strings.TrimSpace(m.Condition.Metric)
	m.Condition.Op = cmp.Or(strings.TrimSpace(m.Condition.Op), AlertOpGTE)

	v := validator.New()
	v.Must(m.Project != "", "project required")
	validAlertName(v, m.Name)
	validAlertTarget(v, m.Target)
	validAlertCondition(v, m.Target.Kind, m.Condition)
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
	if alertTargetKind(t.Kind) == AlertTargetKindCustom {
		return "custom/" + t.Source + "/" + t.Series
	}
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
