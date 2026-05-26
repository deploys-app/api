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
}

// WAFRule mirrors parapet's waf.Rule. Expression is a CEL expression returning
// bool; it is validated server-side by compiling the whole ruleset
// all-or-nothing (the api library has no CEL dependency, so client-side
// validation only covers structure).
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

		if v.Mustf(r.ID != "", "rule %s: id required", ref) {
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

// WAFSet upserts the project's zone, replacing the whole ruleset. Mirrors
// parapet's all-or-nothing SetRules: one bad rule rejects the batch and the
// previous good ruleset stays live.
type WAFSet struct {
	Project     string    `json:"project" yaml:"project"`
	Location    string    `json:"location" yaml:"location"`
	Description string    `json:"description" yaml:"description"`
	Rules       []WAFRule `json:"rules" yaml:"rules"`
}

func (m *WAFSet) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Location != "", "location required")
	validWAFRules(v, m.Rules)

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
		{"LOCATION", "RULES", "STATUS", "AGE"},
	}
	for _, x := range m.Items {
		table = append(table, []string{
			x.Location,
			strconv.Itoa(len(x.Rules)),
			x.Status.Text(),
			age(x.CreatedAt),
		})
	}
	return table
}

type WAFItem struct {
	Project     string    `json:"project" yaml:"project"`
	Location    string    `json:"location" yaml:"location"`
	Description string    `json:"description" yaml:"description"`
	Rules       []WAFRule `json:"rules" yaml:"rules"`
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
		{"PROJECT", "LOCATION", "RULES", "STATUS", "AGE"},
		{
			m.Project,
			m.Location,
			strconv.Itoa(len(m.Rules)),
			m.Status.Text(),
			age(m.CreatedAt),
		},
	}
	return table
}
