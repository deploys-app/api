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
	// Get requires the `waf.get` permission.
	Get(ctx context.Context, m *WAFGet) (*WAFItem, error)
	// List requires the `waf.list` permission.
	List(ctx context.Context, m *WAFList) (*WAFListResult, error)
	// Set requires the `waf.set` permission.
	Set(ctx context.Context, m *WAFSet) (*Empty, error)
	// Delete requires the `waf.delete` permission.
	Delete(ctx context.Context, m *WAFDelete) (*Empty, error)
	// Metrics requires the `waf.get` permission.
	Metrics(ctx context.Context, m *WAFMetrics) (*WAFMetricsResult, error)
	// LimitMetrics requires the `waf.get` permission.
	LimitMetrics(ctx context.Context, m *WAFLimitMetrics) (*WAFLimitMetricsResult, error)
	// Test requires the `waf.get` permission.
	Test(ctx context.Context, m *WAFTest) (*WAFTestResult, error)
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
	// Filter is an optional CEL expression (the same request.* surface as
	// WAFRule.Expression) that scopes the limit: empty means every request,
	// otherwise the limit is evaluated (and counted) only for requests the
	// expression matches. Like rule expressions it is validated structurally
	// here and compiled all-or-nothing by the controller; at runtime an eval
	// error fails OPEN (the limit is skipped), so a buggy filter can never
	// reject legitimate traffic. request.body is always "" in limit filters
	// (rate limits run before body buffering).
	Filter string `json:"filter" yaml:"filter,omitempty"`
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

		l.Filter = strings.TrimSpace(l.Filter)
		v.Mustf(utf8.RuneCountInString(l.Filter) <= WAFMaxExpressionLength, "limit %s: filter must not exceed %d characters", ref, WAFMaxExpressionLength)
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

// WAFLimitMetrics reads a zone's rate-limit decision counts
// (parapet_ratelimit_total, collected per minute into the apiserver) over a
// time range. Series come per (limit, result) so the caller can chart the
// limited share — limited / (allowed + limited) — which is how a shadow-mode
// limit is sized before it is enforced.
type WAFLimitMetrics struct {
	Project   string              `json:"project" yaml:"project"`
	Location  string              `json:"location" yaml:"location"`
	TimeRange WAFMetricsTimeRange `json:"timeRange" yaml:"timeRange"`
}

func (m *WAFLimitMetrics) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Location != "", "location required")
	v.Must(validWAFMetricsTimeRange[m.TimeRange], "timeRange invalid")

	return WrapValidate(v)
}

// WAFLimitMetricsResult mirrors WAFMetricsResult at the (limit, result) grain.
// LimitID is the short, project-local id, matching WAF.Get so the caller can
// join a series to its limit.
type WAFLimitMetricsResult struct {
	Series []*WAFLimitMetricsSeries `json:"series" yaml:"series"`
	Total  float64                  `json:"total" yaml:"total"`
}

type WAFLimitMetricsSeries struct {
	LimitID string       `json:"limitId" yaml:"limitId"`
	Result  string       `json:"result" yaml:"result"` // allowed|limited
	Total   float64      `json:"total" yaml:"total"`   // this series' sum over the range
	Points  [][2]float64 `json:"points" yaml:"points"` // [unixSeconds, count], time-ordered
}

// WAFTest dry-runs a zone draft (or a single expression) against a synthetic
// sample request. Nothing is stored and nothing reaches the cluster; the
// server compiles with the same CEL environment as the parapet engine
// (waf.NewPredicate) and reports what the zone would do.
type WAFTest struct {
	Project  string `json:"project" yaml:"project"`
	Location string `json:"location" yaml:"location"`

	// Expression is single-expression mode: compile/evaluate one CEL
	// expression (same request.* surface as WAFRule.Expression). Mutually
	// exclusive with Rules/Limits.
	Expression string `json:"expression" yaml:"expression"`

	// Rules+Limits are zone-draft mode: the same payload as WAFSet. IDs are
	// used as given (or "#<index>" when empty) — never resolved or generated.
	Rules  []WAFRule  `json:"rules" yaml:"rules"`
	Limits []WAFLimit `json:"limits" yaml:"limits"`

	Request WAFTestRequest `json:"request" yaml:"request"`
}

// WAFTestRequest is the synthetic sample request. country/asn are simulation
// inputs taken verbatim — the server performs NO GeoIP lookup.
type WAFTestRequest struct {
	Method  string            `json:"method" yaml:"method"` // "" = GET
	Path    string            `json:"path" yaml:"path"`     // required, must start with "/"
	Query   string            `json:"query" yaml:"query"`   // raw query string, no leading "?"
	Host    string            `json:"host" yaml:"host"`
	Scheme  string            `json:"scheme" yaml:"scheme"`   // "" = https (sets X-Forwarded-Proto)
	Headers map[string]string `json:"headers" yaml:"headers"` // single value per name
	Cookies map[string]string `json:"cookies" yaml:"cookies"`
	IP      string            `json:"ip" yaml:"ip"`           // request.remote_ip (wins over a headers["x-real-ip"] entry)
	Country string            `json:"country" yaml:"country"` // request.country, e.g. "TH"; "" = unresolved
	ASN     int64             `json:"asn" yaml:"asn"`         // request.asn, e.g. 13335; 0 = unresolved
}

func (m *WAFTest) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Location != "", "location required")

	m.Expression = strings.TrimSpace(m.Expression)
	exprMode := m.Expression != ""
	draftMode := len(m.Rules)+len(m.Limits) > 0
	// An empty zone draft is deliberately not testable: with both
	// discriminators empty the mode is ambiguous, and the outcome would be
	// trivially pass.
	v.Must(exprMode || draftMode, "expression or rules/limits required")
	v.Must(!(exprMode && draftMode), "expression and rules/limits are mutually exclusive")
	if exprMode {
		v.Mustf(utf8.RuneCountInString(m.Expression) <= WAFMaxExpressionLength, "expression must not exceed %d characters", WAFMaxExpressionLength)
	}
	if draftMode {
		validWAFRules(v, m.Rules)
		validWAFLimits(v, m.Limits)
	}

	validWAFTestRequest(v, &m.Request)

	return WrapValidate(v)
}

// validWAFTestRequest validates the structural contract of the sample
// request. method/country casing is normalized server-side, not here.
func validWAFTestRequest(v *validator.Validator, r *WAFTestRequest) {
	if r.Method != "" {
		// an HTTP method is an RFC 7230 token, the same grammar as a field name
		v.Must(validWAFLimitFieldName(r.Method) && len(r.Method) <= 16, "request: method invalid")
	}

	v.Must(r.Path != "", "request: path required")
	if r.Path != "" {
		v.Must(strings.HasPrefix(r.Path, "/"), "request: path must start with /")
	}
	v.Mustf(utf8.RuneCountInString(r.Path) <= WAFTestMaxPathLength, "request: path must not exceed %d characters", WAFTestMaxPathLength)
	v.Mustf(utf8.RuneCountInString(r.Query) <= WAFTestMaxQueryLength, "request: query must not exceed %d characters", WAFTestMaxQueryLength)
	v.Mustf(utf8.RuneCountInString(r.Host) <= WAFTestMaxValueLength, "request: host must not exceed %d characters", WAFTestMaxValueLength)
	v.Must(r.Scheme == "" || r.Scheme == "http" || r.Scheme == "https", "request: scheme invalid (want http|https)")

	v.Mustf(len(r.Headers) <= WAFTestMaxHeaders, "request: headers must not exceed %d entries", WAFTestMaxHeaders)
	for name, value := range r.Headers {
		v.Mustf(validWAFLimitFieldName(name), "request: header %q: name invalid", name)
		// On inbound prod requests net/http moves Host into r.Host, so the
		// engine never sees a headers["host"] entry — letting the sample
		// create one would match expressions that can never match in prod.
		v.Must(!strings.EqualFold(name, "host"), "request: header host not allowed (use the host field)")
		v.Mustf(utf8.RuneCountInString(value) <= WAFTestMaxValueLength, "request: header %q: value must not exceed %d characters", name, WAFTestMaxValueLength)
	}

	v.Mustf(len(r.Cookies) <= WAFTestMaxCookies, "request: cookies must not exceed %d entries", WAFTestMaxCookies)
	for name, value := range r.Cookies {
		v.Mustf(validWAFLimitFieldName(name), "request: cookie %q: name invalid", name)
		v.Mustf(utf8.RuneCountInString(value) <= WAFTestMaxValueLength, "request: cookie %q: value must not exceed %d characters", name, WAFTestMaxValueLength)
	}

	v.Mustf(utf8.RuneCountInString(r.IP) <= WAFTestMaxValueLength, "request: ip must not exceed %d characters", WAFTestMaxValueLength)

	if r.Country != "" {
		v.Must(len(r.Country) == 2 && isASCIILetter(r.Country[0]) && isASCIILetter(r.Country[1]), "request: country must be a 2-letter code")
	}
	v.Must(r.ASN >= 0, "request: asn must not be negative")
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// WAFTestResult reports the dry run. Rules come back in evaluation order
// (ascending priority, stable) — the same order the engine runs them.
type WAFTestResult struct {
	// Outcome mirrors the engine's terminal disposition: pass | allow | block.
	// (Never "error": the dry run reports errors per rule and fails open,
	// matching the engine's default FailMode.)
	Outcome       string `json:"outcome" yaml:"outcome"`
	WinningRuleID string `json:"winningRuleId" yaml:"winningRuleId"` // "" on pass
	Status        int    `json:"status" yaml:"status"`               // block only: response status (default 403); else 0
	Message       string `json:"message" yaml:"message"`             // block only: response body (default "Forbidden"); else ""

	Rules  []WAFTestRuleResult  `json:"rules" yaml:"rules"`
	Limits []WAFTestLimitResult `json:"limits" yaml:"limits"` // input order

	// Valid is false when any rule/limit failed to compile — the same draft
	// would be rejected by waf.set (which compile-validates) and by the
	// engine's all-or-nothing SetRules.
	Valid bool `json:"valid" yaml:"valid"`
}

func (m *WAFTestResult) Table() [][]string {
	matchedRules := 0
	for _, r := range m.Rules {
		if r.Matched {
			matchedRules++
		}
	}
	matchedLimits := 0
	for _, l := range m.Limits {
		if l.FilterMatched {
			matchedLimits++
		}
	}
	return [][]string{
		{"OUTCOME", "RULE", "STATUS", "MATCHED RULES", "MATCHED LIMITS"},
		{
			m.Outcome,
			m.WinningRuleID,
			strconv.Itoa(m.Status),
			strconv.Itoa(matchedRules),
			strconv.Itoa(matchedLimits),
		},
	}
}

type WAFTestRuleResult struct {
	ID       string    `json:"id" yaml:"id"` // echoed input id, or "#<index>" when empty; "expression" in expression mode
	Action   WAFAction `json:"action" yaml:"action"`
	Priority int       `json:"priority" yaml:"priority"`
	Matched  bool      `json:"matched" yaml:"matched"`
	// Evaluated is false for rules after the terminating allow/block — the
	// engine short-circuits there; Matched is still reported (the dry run
	// evaluates every rule independently) so the panel can show all hits.
	Evaluated bool   `json:"evaluated" yaml:"evaluated"`
	Terminal  bool   `json:"terminal" yaml:"terminal"` // this rule decided the outcome
	Error     string `json:"error" yaml:"error"`       // compile or eval error; empty = ok
}

type WAFTestLimitResult struct {
	ID   string `json:"id" yaml:"id"`     // echoed input id, or "#<index>"
	Mode string `json:"mode" yaml:"mode"` // enforce | shadow (echo, defaulted)
	// FilterMatched: the limit's filter selects this request — true when the
	// filter is empty (limit covers everything) or the filter matches.
	FilterMatched bool `json:"filterMatched" yaml:"filterMatched"`
	// Counted: the request would actually be counted against this limit =
	// FilterMatched && Outcome != "block". In the proxy chain the zone WAF
	// runs before the zone rate limiter, so a rule-blocked request never
	// reaches the limiter and burns no rate budget. Whether a counted
	// request would actually be *limited* depends on live counters, which a
	// dry run cannot know.
	Counted bool   `json:"counted" yaml:"counted"`
	Error   string `json:"error" yaml:"error"`
}
