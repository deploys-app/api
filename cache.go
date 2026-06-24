package api

import (
	"context"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/moonrhythm/validator"
)

// Cache manages a project's edge cache-override zone: a single set of
// CEL-filtered cache policy overrides per project per location, applied at the
// parapet edge response cache. A zone maps 1:1 onto a parapet cache zone
// ConfigMap (label parapet.moonrhythm.io/cache: zone) in the location's
// cluster, bound to the project's ingresses via the
// parapet.moonrhythm.io/cache-zone annotation; the overrides map onto parapet's
// cacherule.Override. See the parapet-ingress-controller CACHE.md for the
// engine and evaluation order.
//
// There is at most one zone per (project, location), so it is addressed by
// project + location (no name). Set upserts the whole override set; Delete
// removes the zone entirely.
//
// Cache overrides are EDGE-ONLY (consumed by the edge control plane, never the
// in-cluster controller) and are a distinct capability from the WAF: a role can
// hold cache.* without waf.*. The platform-owned global baseline is not exposed
// here — it is operated in the controller's own namespace and is always
// authoritative over the zone.
type Cache interface {
	// Get requires the `cache.get` permission.
	Get(ctx context.Context, m *CacheGet) (*CacheItem, error)
	// List requires the `cache.list` permission.
	List(ctx context.Context, m *CacheList) (*CacheListResult, error)
	// Set requires the `cache.set` permission.
	Set(ctx context.Context, m *CacheSet) (*Empty, error)
	// Delete requires the `cache.delete` permission.
	Delete(ctx context.Context, m *CacheDelete) (*Empty, error)
	// Metrics requires the `cache.get` permission.
	Metrics(ctx context.Context, m *CacheMetrics) (*CacheMetricsResult, error)
	// ResultMetrics requires the `cache.get` permission.
	ResultMetrics(ctx context.Context, m *CacheResultMetrics) (*CacheResultMetricsResult, error)
}

// CacheOverride mirrors parapet's cacherule.Override: one cache-policy override
// evaluated for every request the zone covers. The yaml tags are snake_case
// because the deployer marshals this struct straight into the parapet
// `overrides:` ConfigMap document — the yaml form IS the parapet wire contract.
// Validation here mirrors parapet's SetOverrides checks so a batch the API
// accepts also compiles in the controller (all-or-nothing).
//
// ID is server-managed and project-local exactly like WAFRule.ID: send "" for a
// new override and the server generates one; echo the existing id (from
// Get/List) to keep an override's identity (and its metric series) across
// edits.
type CacheOverride struct {
	ID          string `json:"id" yaml:"id"`
	Description string `json:"description" yaml:"description"`
	// Action is "cache" (default; force a caching policy onto the fill) or
	// "bypass" (the request skips the cache entirely). ttl/policy/status/stale_*
	// are valid only for action=cache.
	Action string `json:"action" yaml:"action"`
	// Filter is an optional CEL expression (the same request.* surface as
	// WAFRule.Expression) that scopes the override: empty means every request.
	// request.body is always "" here (the cache does not buffer the body). A
	// runtime eval error biases toward NOT caching (the inverse of the rate
	// limiter's fail-open, because caching is the dangerous action). Validated
	// structurally here and compiled all-or-nothing by the controller.
	Filter string `json:"filter" yaml:"filter,omitempty"`
	// TTL is the forced freshness lifetime (a Go duration, 1s..CacheMaxTTL).
	// Required for action=cache; rejected for action=bypass.
	TTL string `json:"ttl" yaml:"ttl,omitempty"`
	// Policy selects how far the force reaches over the origin's Cache-Control:
	// "conservative", "balanced" (default), or "aggressive" (overrides almost
	// everything, including the Authorization gate — a cross-user-leak risk; see
	// CACHE.md). action=cache only.
	Policy string `json:"policy" yaml:"policy,omitempty"`
	// StaleWhileRevalidate / StaleIfError force the RFC 5861 windows (Go
	// durations) for this rule's fills. They ride the forced policy, so they
	// require a ttl. action=cache only.
	StaleWhileRevalidate string `json:"staleWhileRevalidate" yaml:"stale_while_revalidate,omitempty"`
	StaleIfError         string `json:"staleIfError" yaml:"stale_if_error,omitempty"`
	// Status narrows a force to specific origin response statuses. Empty means
	// "every cacheable status the cache already accepts". action=cache only.
	Status []int `json:"status" yaml:"status,omitempty"`
	// Mode is "enforce" (default) or "shadow": shadow evaluates and counts the
	// override but never changes caching, so a rule can be validated against live
	// traffic before it takes effect.
	Mode string `json:"mode" yaml:"mode,omitempty"`
	// Priority orders force rules; the first matching cache rule wins (lower
	// number first, declaration order breaks ties). 0 is resolved to the parapet
	// default (100). Bypass rules are not ordered against each other.
	Priority int `json:"priority" yaml:"priority"`
}

var validCachePolicies = map[string]bool{"": true, "conservative": true, "balanced": true, "aggressive": true}

// validCacheOverrides validates the structural contract of an override set,
// mirroring parapet's SetOverrides checks so a batch the API accepts also
// compiles in the controller (all-or-nothing, like the WAF rules/limits).
func validCacheOverrides(v *validator.Validator, overrides []CacheOverride) {
	v.Mustf(len(overrides) <= CacheMaxOverrides, "overrides must not exceed %d overrides", CacheMaxOverrides)

	seen := make(map[string]bool, len(overrides))
	for i := range overrides {
		o := &overrides[i]
		o.ID = strings.TrimSpace(o.ID)
		o.Action = strings.TrimSpace(o.Action)
		o.Filter = strings.TrimSpace(o.Filter)
		o.TTL = strings.TrimSpace(o.TTL)
		o.Policy = strings.TrimSpace(o.Policy)
		o.StaleWhileRevalidate = strings.TrimSpace(o.StaleWhileRevalidate)
		o.StaleIfError = strings.TrimSpace(o.StaleIfError)
		o.Mode = strings.TrimSpace(o.Mode)

		ref := o.ID
		if ref == "" {
			ref = "#" + strconv.Itoa(i)
		}

		// ID is server-managed (see CacheOverride): "" means "generate one".
		if o.ID != "" {
			v.Mustf(ReValidWAFRuleID.MatchString(o.ID), "override %s: id invalid "+ReValidWAFRuleIDStr, ref)
			v.Mustf(utf8.RuneCountInString(o.ID) <= CacheMaxOverrideIDLength, "override %s: id must not exceed %d characters", ref, CacheMaxOverrideIDLength)
			v.Mustf(!seen[o.ID], "override %s: duplicate id", ref)
			seen[o.ID] = true
		}

		isCache := o.Action == "" || o.Action == "cache"
		v.Mustf(isCache || o.Action == "bypass", "override %s: action invalid (want cache|bypass)", ref)

		if isCache {
			v.Mustf(o.TTL != "", "override %s: ttl required for action=cache", ref)
			if o.TTL != "" {
				d, err := time.ParseDuration(o.TTL)
				if err != nil {
					v.Mustf(false, "override %s: ttl invalid", ref)
				} else {
					v.Mustf(d >= CacheMinTTL && d <= CacheMaxTTL, "override %s: ttl out of bounds (want %s..%s)", ref, CacheMinTTL, CacheMaxTTL)
				}
			}
			v.Mustf(validCachePolicies[o.Policy], "override %s: policy invalid (want conservative|balanced|aggressive)", ref)
			validCacheStaleWindow(v, ref, "staleWhileRevalidate", o.StaleWhileRevalidate)
			validCacheStaleWindow(v, ref, "staleIfError", o.StaleIfError)
			for _, s := range o.Status {
				v.Mustf(s >= 100 && s <= 599, "override %s: status %d invalid (want 100..599)", ref, s)
			}
		} else {
			// bypass: the force-only fields are meaningless and parapet rejects
			// them, so reject them here too rather than silently dropping.
			v.Mustf(o.TTL == "", "override %s: ttl not valid for action=bypass", ref)
			v.Mustf(o.Policy == "", "override %s: policy not valid for action=bypass", ref)
			v.Mustf(o.StaleWhileRevalidate == "" && o.StaleIfError == "", "override %s: stale_* not valid for action=bypass", ref)
			v.Mustf(len(o.Status) == 0, "override %s: status not valid for action=bypass", ref)
		}

		v.Mustf(o.Mode == "" || o.Mode == "enforce" || o.Mode == "shadow", "override %s: mode invalid (want enforce|shadow)", ref)
		v.Mustf(utf8.RuneCountInString(o.Filter) <= CacheMaxFilterLength, "override %s: filter must not exceed %d characters", ref, CacheMaxFilterLength)
	}
}

func validCacheStaleWindow(v *validator.Validator, ref, field, raw string) {
	if raw == "" {
		return
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		v.Mustf(false, "override %s: %s invalid", ref, field)
		return
	}
	v.Mustf(d >= 0, "override %s: %s must be >= 0", ref, field)
}

type CacheGet struct {
	Project  string `json:"project" yaml:"project"`
	Location string `json:"location" yaml:"location"`
}

func (m *CacheGet) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Location != "", "location required")

	return WrapValidate(v)
}

// CacheSet upserts the project's cache zone, replacing the whole override set.
// Mirrors parapet's all-or-nothing SetOverrides: one bad override rejects the
// batch and the previous good set stays live.
type CacheSet struct {
	Project     string          `json:"project" yaml:"project"`
	Location    string          `json:"location" yaml:"location"`
	Description string          `json:"description" yaml:"description"`
	Overrides   []CacheOverride `json:"overrides" yaml:"overrides"`
}

func (m *CacheSet) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Location != "", "location required")
	validCacheOverrides(v, m.Overrides)

	return WrapValidate(v)
}

type CacheDelete struct {
	Project  string `json:"project" yaml:"project"`
	Location string `json:"location" yaml:"location"`
}

func (m *CacheDelete) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Location != "", "location required")

	return WrapValidate(v)
}

type CacheList struct {
	Project string `json:"project" yaml:"project"`
}

func (m *CacheList) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")

	return WrapValidate(v)
}

type CacheListResult struct {
	Project string       `json:"project" yaml:"project"`
	Items   []*CacheItem `json:"items" yaml:"items"`
}

func (m *CacheListResult) Table() [][]string {
	table := [][]string{
		{"LOCATION", "OVERRIDES", "STATUS", "AGE"},
	}
	for _, x := range m.Items {
		table = append(table, []string{
			x.Location,
			strconv.Itoa(len(x.Overrides)),
			x.Status.Text(),
			age(x.CreatedAt),
		})
	}
	return table
}

type CacheItem struct {
	Project     string          `json:"project" yaml:"project"`
	Location    string          `json:"location" yaml:"location"`
	Description string          `json:"description" yaml:"description"`
	Overrides   []CacheOverride `json:"overrides" yaml:"overrides"`
	// Status and Action expose the materialization state: Status is Pending
	// while the deployer is (un)applying the zone and Success once live; Action
	// is Create (set) or Delete (tearing down). Both are read-only.
	Status    Status    `json:"status" yaml:"status"`
	Action    Action    `json:"action" yaml:"action"`
	CreatedAt time.Time `json:"createdAt" yaml:"createdAt"`
	CreatedBy string    `json:"createdBy" yaml:"createdBy"`
}

func (m *CacheItem) Table() [][]string {
	table := [][]string{
		{"PROJECT", "LOCATION", "OVERRIDES", "STATUS", "AGE"},
		{
			m.Project,
			m.Location,
			strconv.Itoa(len(m.Overrides)),
			m.Status.Text(),
			age(m.CreatedAt),
		},
	}
	return table
}

// CacheMetrics reads a zone's override decision counts
// (parapet_cache_override_total, collected per minute into the apiserver) over a
// time range. Series come per (override, action, result) so the caller can
// chart the applied share and validate a shadow-mode override before it is
// enforced. Reuses WAFMetricsTimeRange.
type CacheMetrics struct {
	Project   string              `json:"project" yaml:"project"`
	Location  string              `json:"location" yaml:"location"`
	TimeRange WAFMetricsTimeRange `json:"timeRange" yaml:"timeRange"`
}

func (m *CacheMetrics) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Location != "", "location required")
	v.Must(validWAFMetricsTimeRange[m.TimeRange], "timeRange invalid")

	return WrapValidate(v)
}

// CacheMetricsResult carries decision counts at the (override, action, result)
// grain: Series for the time chart plus the grand Total. OverrideID is the
// short, project-local id, matching Cache.Get so the caller can join a series to
// its override.
type CacheMetricsResult struct {
	Series []*CacheMetricsSeries `json:"series" yaml:"series"`
	Total  float64               `json:"total" yaml:"total"`
}

type CacheMetricsSeries struct {
	OverrideID string       `json:"overrideId" yaml:"overrideId"`
	Action     string       `json:"action" yaml:"action"` // cache|bypass
	Result     string       `json:"result" yaml:"result"` // applied|shadow|error
	Total      float64      `json:"total" yaml:"total"`   // this series' sum over the range
	Points     [][2]float64 `json:"points" yaml:"points"` // [unixSeconds, count], time-ordered
}

// CacheResultMetrics reads a project's edge response-cache outcome counts —
// requests served by result (HIT/MISS/STALE/BYPASS, from parapet_cache_total)
// and the bytes served by result (HIT/STALE/MISS, from parapet_cache_egress_bytes)
// — over a time range, summed across all of the project's locations. It powers
// the project cache page's hit-ratio chart; the caller toggles between the
// requests and bytes view per result. Reuses WAFMetricsTimeRange.
type CacheResultMetrics struct {
	Project   string              `json:"project" yaml:"project"`
	TimeRange WAFMetricsTimeRange `json:"timeRange" yaml:"timeRange"`
}

func (m *CacheResultMetrics) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(validWAFMetricsTimeRange[m.TimeRange], "timeRange invalid")

	return WrapValidate(v)
}

// CacheResultMetricsResult carries one series per cache result. Requests and
// Bytes are independent time series so the caller can chart either view; Bytes
// is empty/zero for BYPASS (bypassed responses are served from the origin and
// carry no cache egress).
type CacheResultMetricsResult struct {
	Series []*CacheResultSeries `json:"series" yaml:"series"`
}

type CacheResultSeries struct {
	Result        string       `json:"result" yaml:"result"`               // HIT|MISS|STALE|BYPASS
	Requests      [][2]float64 `json:"requests" yaml:"requests"`           // [unixSeconds, request count], time-ordered
	Bytes         [][2]float64 `json:"bytes" yaml:"bytes"`                 // [unixSeconds, bytes served], time-ordered
	RequestsTotal float64      `json:"requestsTotal" yaml:"requestsTotal"` // sum of requests over the range
	BytesTotal    float64      `json:"bytesTotal" yaml:"bytesTotal"`       // sum of bytes over the range
}
