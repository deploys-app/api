package api

import (
	"context"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/moonrhythm/validator"
)

// WAF manages a project's WAF zone: a single CEL ruleset per project per
// location that protects every route the project has in that location. A zone
// maps 1:1 onto a parapet zone ConfigMap in the location's cluster; rules map
// onto parapet's waf.Rule. See the parapet-ingress-controller WAF.md for the
// engine and evaluation order.
//
// There is at most one zone per (project, location), so it is addressed by
// project + location (no name). Set upserts the whole ruleset; Delete removes
// the zone entirely.
//
// The platform-owned global baseline is not exposed here — it is operated in
// the controller's own namespace and is always authoritative over the zone.
type WAF interface {
	Get(ctx context.Context, m *WAFGet) (*WAFItem, error)
	List(ctx context.Context, m *WAFList) (*WAFListResult, error)
	Set(ctx context.Context, m *WAFSet) (*Empty, error)
	Delete(ctx context.Context, m *WAFDelete) (*Empty, error)
	Metrics(ctx context.Context, m *WAFMetrics) (*WAFMetricsResult, error)
}

// WAFRule mirrors parapet's waf.Rule. Expression is a CEL expression returning
// bool; it is validated server-side by compiling the whole ruleset
// all-or-nothing (the api library has no CEL dependency, so client-side
// validation only covers structure).
//
// ID is server-managed and project-local: a short, opaque id the server
// assigns. (Internally it is prefixed with the project id so parapet's
// parapet_waf_matches{rule_id} can be attributed back to the project, but that
// prefix is stripped from responses and re-applied to requests — clients never
// see or send it.) Clients do not pick it — send "" for a new rule and the
// server generates one; echo the existing id (from Get/List) to keep a rule's
// id (and its metric series) across edits. An id that wasn't previously issued
// to this project is regenerated server-side.
type WAFRule struct {
	ID          string    `json:"id" yaml:"id"`
	Description string    `json:"description" yaml:"description"`
	Expression  string    `json:"expression" yaml:"expression"`
	Action      WAFAction `json:"action" yaml:"action"`
	Status      int       `json:"status" yaml:"status"`   // block only; 0 = default 403
	Message     string    `json:"message" yaml:"message"` // block only; "" = default "Forbidden"
	Priority    int       `json:"priority" yaml:"priority"`
}

// validWAFRules validates the structural contract of a ruleset. CEL semantics
// are not checked here — the server compiles the batch all-or-nothing.
func validWAFRules(v *validator.Validator, rules []WAFRule) {
	v.Mustf(len(rules) <= WAFMaxRules, "rules must not exceed %d rules", WAFMaxRules)

	seen := make(map[string]bool, len(rules))
	for i := range rules {
		r := &rules[i]
		r.ID = strings.TrimSpace(r.ID)
		r.Expression = strings.TrimSpace(r.Expression)

		ref := r.ID
		if ref == "" {
			ref = "#" + strconv.Itoa(i)
		}

		// ID is server-managed (see WAFRule): "" means "generate one". Only
		// validate an echoed id's shape/uniqueness; the server still regenerates
		// any id it didn't issue to this project.
		if r.ID != "" {
			v.Mustf(ReValidWAFRuleID.MatchString(r.ID), "rule %s: id invalid "+ReValidWAFRuleIDStr, ref)
			v.Mustf(utf8.RuneCountInString(r.ID) <= WAFMaxRuleIDLength, "rule %s: id must not exceed %d characters", ref, WAFMaxRuleIDLength)
			v.Mustf(!seen[r.ID], "rule %s: duplicate id", ref)
			seen[r.ID] = true
		}

		v.Mustf(r.Expression != "", "rule %s: expression required", ref)
		v.Mustf(utf8.RuneCountInString(r.Expression) <= WAFMaxExpressionLength, "rule %s: expression must not exceed %d characters", ref, WAFMaxExpressionLength)
		v.Mustf(r.Action.Valid(), "rule %s: action invalid", ref)
		if r.Status != 0 {
			v.Mustf(r.Status >= 100 && r.Status <= 599, "rule %s: status invalid", ref)
		}
		v.Mustf(utf8.RuneCountInString(r.Message) <= WAFMaxMessageLength, "rule %s: message must not exceed %d characters", ref, WAFMaxMessageLength)
	}
}

// WAFLimit mirrors parapet's ratelimitrule.Limit: one rate limit evaluated for
// every request the zone covers. Limits live on the same zone as the rules but
// materialize into a separate parapet ratelimit zone (label/annotation pair
// parapet.moonrhythm.io/ratelimit{,-zone}); see the parapet-ingress-controller
// ratelimitrule package for the engine.
//
// ID is server-managed exactly like WAFRule.ID: send "" for a new limit, echo
// the existing id to keep a limit's identity (and its live counters / metric
// series) across edits.
type WAFLimit struct {
	ID          string `json:"id" yaml:"id"`
	Description string `json:"description" yaml:"description"`
	// Key lists the characteristics composed into the bucket key (default
	// ["ip"]): ip, host, asn, country, header:<name>, cookie:<name>
	// ("ip-host" is accepted as an alias for ip + host).
	Key       []string `json:"key" yaml:"key"`
	Rate      int      `json:"rate" yaml:"rate"`                     // max requests per Window per key; > 0
	Window    string   `json:"window" yaml:"window"`                 // Go duration, 1s..1h
	Algorithm string   `json:"algorithm" yaml:"algorithm,omitempty"` // "" = fixed | sliding
	Mode      string   `json:"mode" yaml:"mode,omitempty"`           // "" = enforce | shadow
	Status    int      `json:"status" yaml:"status,omitempty"`       // 0 = default 429 | 503
	Message   string   `json:"message" yaml:"message,omitempty"`     // "" = default "Too Many Requests"
}

// wafLimitKeyTakesName lists the key characteristics that take a :<name>
// suffix; wafLimitBareKeys those that don't.
var (
	wafLimitKeyTakesName = map[string]bool{"header": true, "cookie": true}
	wafLimitBareKeys     = map[string]bool{"ip": true, "host": true, "ip-host": true, "asn": true, "country": true}
)

// validWAFLimitFieldName reports whether a header/cookie name is a valid HTTP
// token (RFC 7230), mirroring parapet's validateFieldName.
func validWAFLimitFieldName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		switch c := name[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// validWAFLimits validates the structural contract of a limit set, mirroring
// parapet's SetLimits checks so a batch the API accepts also compiles in the
// controller (all-or-nothing, like the rules).
func validWAFLimits(v *validator.Validator, limits []WAFLimit) {
	v.Mustf(len(limits) <= WAFMaxLimits, "limits must not exceed %d limits", WAFMaxLimits)

	seen := make(map[string]bool, len(limits))
	for i := range limits {
		l := &limits[i]
		l.ID = strings.TrimSpace(l.ID)
		l.Window = strings.TrimSpace(l.Window)

		ref := l.ID
		if ref == "" {
			ref = "#" + strconv.Itoa(i)
		}

		// ID is server-managed (see WAFLimit): "" means "generate one".
		if l.ID != "" {
			v.Mustf(ReValidWAFRuleID.MatchString(l.ID), "limit %s: id invalid "+ReValidWAFRuleIDStr, ref)
			v.Mustf(utf8.RuneCountInString(l.ID) <= WAFMaxLimitIDLength, "limit %s: id must not exceed %d characters", ref, WAFMaxLimitIDLength)
			v.Mustf(!seen[l.ID], "limit %s: duplicate id", ref)
			seen[l.ID] = true
		}

		for _, k := range l.Key {
			key, name, hasName := strings.Cut(k, ":")
			switch {
			case hasName && wafLimitKeyTakesName[key]:
				v.Mustf(validWAFLimitFieldName(name), "limit %s: key %s: invalid name", ref, key)
			case hasName:
				v.Mustf(false, "limit %s: key %q does not take a :<name> suffix", ref, key)
			case wafLimitKeyTakesName[key]:
				v.Mustf(false, "limit %s: key %s: missing name (want %s:<name>)", ref, key, key)
			default:
				v.Mustf(wafLimitBareKeys[key], "limit %s: unknown key %q (want ip|host|asn|country|header:<name>|cookie:<name>)", ref, k)
			}
		}

		v.Mustf(l.Rate > 0, "limit %s: rate must be greater than 0", ref)

		v.Mustf(l.Window != "", "limit %s: window required", ref)
		if l.Window != "" {
			d, err := time.ParseDuration(l.Window)
			if err != nil {
				v.Mustf(false, "limit %s: window invalid", ref)
			} else {
				v.Mustf(d >= WAFLimitMinWindow && d <= WAFLimitMaxWindow, "limit %s: window out of bounds (want %s..%s)", ref, WAFLimitMinWindow, WAFLimitMaxWindow)
			}
		}

		v.Mustf(l.Algorithm == "" || l.Algorithm == "fixed" || l.Algorithm == "sliding", "limit %s: algorithm invalid (want fixed|sliding)", ref)
		v.Mustf(l.Mode == "" || l.Mode == "enforce" || l.Mode == "shadow", "limit %s: mode invalid (want enforce|shadow)", ref)
		v.Mustf(l.Status == 0 || l.Status == 429 || l.Status == 503, "limit %s: status invalid (want 429 or 503)", ref)
		v.Mustf(utf8.RuneCountInString(l.Message) <= WAFMaxMessageLength, "limit %s: message must not exceed %d characters", ref, WAFMaxMessageLength)
	}
}

type WAFGet struct {
	Project  string `json:"project" yaml:"project"`
	Location string `json:"location" yaml:"location"`
}

func (m *WAFGet) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Location != "", "location required")

	return WrapValidate(v)
}

// WAFSet upserts the project's zone, replacing the whole ruleset and limit
// set. Mirrors parapet's all-or-nothing SetRules/SetLimits: one bad rule or
// limit rejects the batch and the previous good set stays live.
type WAFSet struct {
	Project     string     `json:"project" yaml:"project"`
	Location    string     `json:"location" yaml:"location"`
	Description string     `json:"description" yaml:"description"`
	Rules       []WAFRule  `json:"rules" yaml:"rules"`
	Limits      []WAFLimit `json:"limits" yaml:"limits"`
}

func (m *WAFSet) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Location != "", "location required")
	validWAFRules(v, m.Rules)
	validWAFLimits(v, m.Limits)

	return WrapValidate(v)
}

type WAFDelete struct {
	Project  string `json:"project" yaml:"project"`
	Location string `json:"location" yaml:"location"`
}

func (m *WAFDelete) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Location != "", "location required")

	return WrapValidate(v)
}

type WAFList struct {
	Project string `json:"project" yaml:"project"`
}

func (m *WAFList) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")

	return WrapValidate(v)
}

type WAFListResult struct {
	Project string     `json:"project" yaml:"project"`
	Items   []*WAFItem `json:"items" yaml:"items"`
}

func (m *WAFListResult) Table() [][]string {
	table := [][]string{
		{"LOCATION", "RULES", "LIMITS", "STATUS", "AGE"},
	}
	for _, x := range m.Items {
		table = append(table, []string{
			x.Location,
			strconv.Itoa(len(x.Rules)),
			strconv.Itoa(len(x.Limits)),
			x.Status.Text(),
			age(x.CreatedAt),
		})
	}
	return table
}

type WAFItem struct {
	Project     string     `json:"project" yaml:"project"`
	Location    string     `json:"location" yaml:"location"`
	Description string     `json:"description" yaml:"description"`
	Rules       []WAFRule  `json:"rules" yaml:"rules"`
	Limits      []WAFLimit `json:"limits" yaml:"limits"`
	// Status and Action expose the materialization state: Status is Pending
	// while the deployer is (un)applying the zone and Success once live; Action
	// is Create (set) or Delete (tearing down). Both are read-only.
	Status    Status    `json:"status" yaml:"status"`
	Action    Action    `json:"action" yaml:"action"`
	CreatedAt time.Time `json:"createdAt" yaml:"createdAt"`
	CreatedBy string    `json:"createdBy" yaml:"createdBy"`
}

func (m *WAFItem) Table() [][]string {
	table := [][]string{
		{"PROJECT", "LOCATION", "RULES", "LIMITS", "STATUS", "AGE"},
		{
			m.Project,
			m.Location,
			strconv.Itoa(len(m.Rules)),
			strconv.Itoa(len(m.Limits)),
			m.Status.Text(),
			age(m.CreatedAt),
		},
	}
	return table
}

// WAFMetrics reads a zone's match counts (parapet_waf_matches, collected per
// minute into the apiserver) over a time range, for charting and totals.
type WAFMetricsTimeRange string

const (
	WAFMetricsTimeRange1h  WAFMetricsTimeRange = "1h"
	WAFMetricsTimeRange6h  WAFMetricsTimeRange = "6h"
	WAFMetricsTimeRange12h WAFMetricsTimeRange = "12h"
	WAFMetricsTimeRange1d  WAFMetricsTimeRange = "1d"
	WAFMetricsTimeRange7d  WAFMetricsTimeRange = "7d"
	WAFMetricsTimeRange30d WAFMetricsTimeRange = "30d" // = waf_usages TTL
)

var validWAFMetricsTimeRange = map[WAFMetricsTimeRange]bool{
	WAFMetricsTimeRange1h:  true,
	WAFMetricsTimeRange6h:  true,
	WAFMetricsTimeRange12h: true,
	WAFMetricsTimeRange1d:  true,
	WAFMetricsTimeRange7d:  true,
	WAFMetricsTimeRange30d: true,
}

type WAFMetrics struct {
	Project   string              `json:"project" yaml:"project"`
	Location  string              `json:"location" yaml:"location"`
	TimeRange WAFMetricsTimeRange `json:"timeRange" yaml:"timeRange"`
}

func (m *WAFMetrics) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Location != "", "location required")
	v.Must(validWAFMetricsTimeRange[m.TimeRange], "timeRange invalid")

	return WrapValidate(v)
}

// WAFMetricsResult carries match counts at the (rule, action) grain: Series for
// the time chart, plus per-series and grand Totals for the range sum / top rules.
// RuleID is the short, project-local id, matching WAF.Get so the caller can join
// a series to its rule.
type WAFMetricsResult struct {
	Series []*WAFMetricsSeries `json:"series" yaml:"series"`
	Total  float64             `json:"total" yaml:"total"`
}

type WAFMetricsSeries struct {
	RuleID string       `json:"ruleId" yaml:"ruleId"`
	Action string       `json:"action" yaml:"action"`
	Total  float64      `json:"total" yaml:"total"`   // this series' sum over the range
	Points [][2]float64 `json:"points" yaml:"points"` // [unixSeconds, count], time-ordered
}
