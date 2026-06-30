package api

import (
	"context"
	"net/textproto"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/moonrhythm/validator"
)

// Transform manages a project's declarative request/response transform zone: a
// per-(project, location) ordered set of rules applied in the parapet proxy
// layer. Each rule runs in exactly one phase (request|response), is optionally
// scoped by a CEL Filter over request.*, and applies an ordered list of ops of
// that phase. A zone maps 1:1 onto a parapet transform zone ConfigMap (label
// parapet.moonrhythm.io/transform: zone) in the location's cluster, bound to the
// project's ingresses via the parapet.moonrhythm.io/transform-zone annotation.
//
// There is at most one zone per (project, location), so it is addressed by
// project + location (no name). Set replaces the whole rule set, mirroring
// parapet's all-or-nothing reload: one bad rule rejects the batch and the
// previous good set stays live. The api library has no CEL dependency; the
// Filter is validated structurally here and compiled all-or-nothing by the
// parapet controller. A Filter that fails to COMPILE rejects the whole batch
// (the previous good set stays live, no partial apply); a Filter that errors at
// EVAL skips only that one rule (no mutation), so a buggy predicate never
// applies an unintended transform.
//
// The api collection field, the DeployerCommand field, and the parapet wire
// document root key are all transforms/Transforms (aligned with parapet's
// transformrule.Document{ Transforms ... yaml:"transforms" }). The DB JSONB
// column stays rules — an internal column name, not a wire contract.
//
// transform.get/transform.list are explicitly non-public-bindable (an op value
// can carry a credential), a deliberate deviation from cache/waf whose reads are
// public-bindable; see role.go. Metrics are deferred to Phase 2 (needs parapet
// to emit parapet_transform_matches); ids stay project-prefixed so the series
// attaches later without a breaking change.
type Transform interface {
	// Get requires the `transform.get` permission.
	Get(ctx context.Context, m *TransformGet) (*TransformItem, error)
	// List requires the `transform.list` permission.
	List(ctx context.Context, m *TransformList) (*TransformListResult, error)
	// Set requires the `transform.set` permission. Replaces the whole rule set.
	Set(ctx context.Context, m *TransformSet) (*Empty, error)
	// Delete requires the `transform.delete` permission.
	Delete(ctx context.Context, m *TransformDelete) (*Empty, error)
	// Metrics deferred to Phase 2 (needs parapet to emit parapet_transform_matches).
}

// Op type vocabulary (frozen, v1). Header ops are phase-polymorphic: their phase
// is the rule's Phase. The legality of each op within a phase is enforced by
// validTransformRules (the §2.3 matrix).
const (
	TransformOpSetHeader    = "set-header"    // request|response
	TransformOpRemoveHeader = "remove-header" // request|response
	TransformOpRewritePath  = "rewrite-path"  // request
	TransformOpRewriteQuery = "rewrite-query" // request
	TransformOpRedirect     = "redirect"      // request (short-circuit; sole op)
	TransformOpSetStatus    = "set-status"    // response
	TransformOpCORS         = "cors"          // response (dual-seam; sole op)
)

// transformRequestOps / transformResponseOps are the phase×op legality matrix.
// set-header/remove-header appear in both because they are phase-polymorphic.
var (
	transformRequestOps = map[string]bool{
		TransformOpSetHeader:    true,
		TransformOpRemoveHeader: true,
		TransformOpRewritePath:  true,
		TransformOpRewriteQuery: true,
		TransformOpRedirect:     true,
	}
	transformResponseOps = map[string]bool{
		TransformOpSetHeader:    true,
		TransformOpRemoveHeader: true,
		TransformOpSetStatus:    true,
		TransformOpCORS:         true,
	}
)

// transformRedirectStatuses is the set of redirect statuses redirect accepts
// (0 resolves to the default 302 at the controller).
var transformRedirectStatuses = map[int]bool{301: true, 302: true, 303: true, 307: true, 308: true}

// transformSharedProtectedHeaders are hop-by-hop + framing headers rejected on
// set-header/remove-header in BOTH phases: mutating any of them corrupts
// request/response framing or connection management. Keys are canonical header
// names (textproto.CanonicalMIMEHeaderKey form).
var transformSharedProtectedHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Transfer-Encoding":   true,
	"Te":                  true, // canonical form of "TE"
	"Trailer":             true,
	"Upgrade":             true,
	"Proxy-Connection":    true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Content-Length":      true,
	"Content-Encoding":    true, // setting it without re-encoding the stream corrupts the body
}

// transformWAFClaimHeader is the literal value of parapet's wafclaim.Header
// constant. api cannot import parapet, so this MUST be kept in sync with
// parapet-ingress-controller's wafclaim.Header (currently "X-Parapet-Waf"). A
// transform must never set/spoof it: the Director deletes it on every proxied
// request, and it carries the edge→core "WAF already validated" claim.
const transformWAFClaimHeader = "X-Parapet-Waf"

// transformRequestProtectedHeaders are additionally rejected in the REQUEST
// phase only: spoofing them forges the client identity / trust chain that the
// edge, WAF/ratelimit, forward-auth, and origins rely on. Keys are canonical
// header names. X-Forwarded-* is matched as a canonical-name prefix separately
// (transformForwardedPrefix), covering For/Host/Proto/Port/Method/Uri.
//
// NOTE: the per-route forward-auth authResponseHeaders names (§3.6) cannot be
// enforced here — the api library has no route context — so that check is
// deferred to the apiserver, which does. This static set covers the fixed
// identity headers.
var transformRequestProtectedHeaders = map[string]bool{
	"Host": true, // use the route Host override (RouteConfig.Host) instead
	textproto.CanonicalMIMEHeaderKey(transformWAFClaimHeader): true,
	"X-Real-Ip":    true, // canonical form of "X-Real-IP"
	"X-Auth-Email": true, // forward-auth identity
	"X-Auth-User":  true, // forward-auth identity
}

const transformForwardedPrefix = "X-Forwarded-" // canonical-name prefix match

// transformHeaderProtected reports whether a header name is on the protected
// denylist for the given phase (§3.6). name must already be a valid RFC 7230
// token; it is canonicalized before lookup so the check is case-insensitive on
// the canonical header name.
func transformHeaderProtected(phase TransformPhase, name string) bool {
	canon := textproto.CanonicalMIMEHeaderKey(name)
	if transformSharedProtectedHeaders[canon] {
		return true
	}
	if phase == TransformPhaseRequest {
		if transformRequestProtectedHeaders[canon] {
			return true
		}
		if strings.HasPrefix(canon, transformForwardedPrefix) {
			return true
		}
	}
	return false
}

// TransformRule is a phase + optional CEL scope + an ordered list of ops, all of
// that phase. snake_case yaml tags ARE the parapet wire contract (the cache
// lesson). Phase is a *pointer so an omitted phase is a hard validation error,
// not a silent request-phase default.
type TransformRule struct {
	ID          string          `json:"id" yaml:"id"`
	Description string          `json:"description" yaml:"description"`
	Phase       *TransformPhase `json:"phase" yaml:"phase"`             // request | response (REQUIRED, PRIMARY axis)
	Filter      string          `json:"filter" yaml:"filter,omitempty"` // CEL over request.*; "" = always; eval-error => skip
	Ops         []TransformOp   `json:"ops" yaml:"ops"`                 // applied in array order; all must belong to Phase
	Mode        string          `json:"mode" yaml:"mode,omitempty"`     // "" = enforce | shadow (match+count, apply nothing)
	Priority    int             `json:"priority" yaml:"priority"`       // ascending within a phase; ties by id
}

// TransformOp is flat and omitempty-driven (mirrors CacheOverride). Each op
// reads only its own subset of fields; unrelated fields are zero and drop out of
// the yaml.
type TransformOp struct {
	Type string `json:"type" yaml:"type"` // op id (see vocabulary)

	// header ops (request or response per the rule's Phase)
	Name  string `json:"name" yaml:"name,omitempty"`   // header name
	Value string `json:"value" yaml:"value,omitempty"` // set-header value

	// redirect (request)
	To string `json:"to" yaml:"to,omitempty"` // redirect target; "$uri" => original RequestURI

	// rewrite-path (request)
	Path    string `json:"path" yaml:"path,omitempty"`       // literal replacement path (starts with /)
	Regex   string `json:"regex" yaml:"regex,omitempty"`     // RE2 over request path
	Replace string `json:"replace" yaml:"replace,omitempty"` // replacement ($1, ${name})

	// rewrite-query (request)
	Query       map[string]string `json:"query" yaml:"query,omitempty"` // set/overwrite these query params
	RemoveQuery []string          `json:"removeQuery" yaml:"remove_query,omitempty"`

	// redirect / set-status
	Status int `json:"status" yaml:"status,omitempty"` // redirect 3xx | set-status 100..599

	// cors — the dual-seam op: authored in a response-phase rule, but parapet
	// mounts it as a standalone request-spanning cors.CORS middleware (NOT via
	// the response interceptor), so its OPTIONS preflight short-circuit fires at
	// request time. Must be the only op in its rule.
	AllowOrigins     []string `json:"allowOrigins" yaml:"allow_origins,omitempty"`
	AllowMethods     []string `json:"allowMethods" yaml:"allow_methods,omitempty"`
	AllowHeaders     []string `json:"allowHeaders" yaml:"allow_headers,omitempty"`
	ExposeHeaders    []string `json:"exposeHeaders" yaml:"expose_headers,omitempty"`
	AllowCredentials bool     `json:"allowCredentials" yaml:"allow_credentials,omitempty"`
	MaxAge           string   `json:"maxAge" yaml:"max_age,omitempty"` // Go duration
}

// validTransformRules validates the structural contract of a transform rule set,
// mirroring validCacheOverrides/validWAFRules. NO CEL parsing (the api library
// has no CEL dependency; the Filter is compiled all-or-nothing at the
// controller). All-or-nothing: one bad rule rejects the batch and the previous
// good set stays live.
func validTransformRules(v *validator.Validator, transforms []TransformRule) {
	v.Mustf(len(transforms) <= TransformMaxRules, "transforms must not exceed %d rules", TransformMaxRules)

	seen := make(map[string]bool, len(transforms))
	for i := range transforms {
		r := &transforms[i]
		r.ID = strings.TrimSpace(r.ID)
		r.Filter = strings.TrimSpace(r.Filter)
		r.Mode = strings.TrimSpace(r.Mode)

		ref := r.ID
		if ref == "" {
			ref = "#" + strconv.Itoa(i)
		}

		// ID is server-managed (mirrors WAFRule/CacheOverride): "" means
		// "generate one". Only validate an echoed id's shape/uniqueness.
		if r.ID != "" {
			v.Mustf(ReValidWAFRuleID.MatchString(r.ID), "rule %s: id invalid "+ReValidWAFRuleIDStr, ref)
			v.Mustf(utf8.RuneCountInString(r.ID) <= TransformMaxRuleIDLength, "rule %s: id must not exceed %d characters", ref, TransformMaxRuleIDLength)
			v.Mustf(!seen[r.ID], "rule %s: duplicate id", ref)
			seen[r.ID] = true
		}

		// Phase is required (a nil phase is rejected, see TransformPhase) and must
		// be a known value.
		v.Mustf(r.Phase != nil, "rule %s: phase required", ref)
		phaseOK := r.Phase != nil && r.Phase.Valid()
		if r.Phase != nil {
			v.Mustf(r.Phase.Valid(), "rule %s: phase invalid (want request|response)", ref)
		}

		// Mode is "" (enforce, the default) or "shadow" only — NOT "enforce".
		// The parapet transformrule wire contract switches on {"", "shadow"} and
		// rejects the whole zone all-or-nothing on any other value, so accepting
		// "enforce" here would let a CLI/MCP caller silently disable an entire
		// ruleset (the controller keeps the last-good zone). "" already means
		// enforce; the console emits "" or "shadow".
		v.Mustf(r.Mode == "" || r.Mode == "shadow", "rule %s: mode invalid (want empty or shadow)", ref)
		v.Mustf(utf8.RuneCountInString(r.Filter) <= TransformMaxFilterLength, "rule %s: filter must not exceed %d characters", ref, TransformMaxFilterLength)

		v.Mustf(len(r.Ops) >= 1, "rule %s: at least one op required", ref)
		v.Mustf(len(r.Ops) <= TransformMaxOpsPerRule, "rule %s: ops must not exceed %d ops", ref, TransformMaxOpsPerRule)

		// Op-level checks require a known phase to evaluate the legality matrix; if
		// the phase is missing/invalid the phase error above already fails the
		// batch, so skip the per-op phase-dependent checks for this rule.
		if !phaseOK {
			continue
		}
		phase := *r.Phase

		// Short-circuit / single-mount ops must be the only op in their rule:
		// redirect short-circuits (later ops would be dead code); cors is mounted
		// as a standalone middleware and cannot participate in in-rule ordering.
		for j := range r.Ops {
			t := strings.TrimSpace(r.Ops[j].Type)
			if (t == TransformOpRedirect || t == TransformOpCORS) && len(r.Ops) != 1 {
				v.Mustf(false, "rule %s: op %s must be the only op in its rule", ref, t)
				break
			}
		}

		for j := range r.Ops {
			validTransformOp(v, ref, j, phase, &r.Ops[j])
		}
	}
}

// validTransformOp validates one op against the rule's phase and the per-op arg
// rules (§3.5) and the protected-header denylist (§3.6).
func validTransformOp(v *validator.Validator, ref string, idx int, phase TransformPhase, o *TransformOp) {
	o.Type = strings.TrimSpace(o.Type)
	o.Name = strings.TrimSpace(o.Name)
	o.To = strings.TrimSpace(o.To)
	o.Path = strings.TrimSpace(o.Path)
	o.Regex = strings.TrimSpace(o.Regex)
	o.MaxAge = strings.TrimSpace(o.MaxAge)

	opref := ref + " op #" + strconv.Itoa(idx)

	// Every op's type must be legal for the rule's phase (the §2.3 matrix).
	legal := transformRequestOps
	if phase == TransformPhaseResponse {
		legal = transformResponseOps
	}
	if !legal[o.Type] {
		v.Mustf(false, "%s: op %q not valid for phase %s", opref, o.Type, phase.String())
		return
	}

	switch o.Type {
	case TransformOpSetHeader, TransformOpRemoveHeader:
		v.Mustf(o.Name != "", "%s: name required", opref)
		if o.Name != "" {
			v.Mustf(validTransformHeaderName(o.Name), "%s: name %q is not a valid header field-name", opref, o.Name)
			v.Mustf(!transformHeaderProtected(phase, o.Name), "%s: header %q is protected and cannot be %s in the %s phase", opref, o.Name, o.Type, phase.String())
		}
		if o.Type == TransformOpSetHeader {
			v.Mustf(utf8.RuneCountInString(o.Value) <= TransformMaxHeaderValueLength, "%s: value must not exceed %d characters", opref, TransformMaxHeaderValueLength)
		}

	case TransformOpRewritePath:
		hasPath := o.Path != ""
		hasRegex := o.Regex != ""
		v.Mustf(hasPath != hasRegex, "%s: exactly one of path or regex+replace required", opref)
		if hasPath {
			v.Mustf(strings.HasPrefix(o.Path, "/"), "%s: path must start with /", opref)
		}
		if hasRegex {
			v.Mustf(o.Replace != "", "%s: replace required when regex is set", opref)
			// The one place api pre-compiles: regexp is RE2 (not a CEL dependency).
			if _, err := regexp.Compile(o.Regex); err != nil {
				v.Mustf(false, "%s: regex invalid: %v", opref, err)
			}
		}

	case TransformOpRewriteQuery:
		v.Mustf(len(o.Query) > 0 || len(o.RemoveQuery) > 0, "%s: at least one of query or removeQuery required", opref)
		for k := range o.Query {
			v.Mustf(strings.TrimSpace(k) != "", "%s: query key must not be empty", opref)
		}
		for _, k := range o.RemoveQuery {
			v.Mustf(strings.TrimSpace(k) != "", "%s: removeQuery key must not be empty", opref)
		}

	case TransformOpRedirect:
		v.Mustf(o.To != "", "%s: to required", opref)
		if o.To != "" {
			v.Mustf(validTransformRedirectTo(o.To), "%s: to must be a /-relative path or a valid http(s):// URL (only the $uri placeholder is allowed)", opref)
		}
		v.Mustf(o.Status == 0 || transformRedirectStatuses[o.Status], "%s: status invalid (want 301|302|303|307|308)", opref)

	case TransformOpSetStatus:
		v.Mustf(o.Status >= 100 && o.Status <= 599, "%s: status invalid (want 100..599)", opref)

	case TransformOpCORS:
		v.Mustf(len(o.AllowOrigins) > 0, "%s: allowOrigins required", opref)
		if o.AllowCredentials {
			for _, origin := range o.AllowOrigins {
				v.Mustf(strings.TrimSpace(origin) != "*", "%s: allowOrigins must not contain \"*\" when allowCredentials is true", opref)
			}
		}
		if o.MaxAge != "" {
			if _, err := time.ParseDuration(o.MaxAge); err != nil {
				v.Mustf(false, "%s: maxAge invalid (want a Go duration)", opref)
			}
		}
	}
}

// validTransformHeaderName reports whether a header name is a valid HTTP
// field-name token (RFC 7230). Mirrors validWAFLimitFieldName.
func validTransformHeaderName(name string) bool {
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

// validTransformRedirectTo reports whether a redirect target is either a
// /-relative path or a syntactically valid http(s):// absolute URL. The single
// allowed $uri placeholder is stripped for structural validation. A
// scheme-relative "//host" target is rejected (it is neither clean-relative nor
// http(s):// absolute, and is an open-redirect foot-gun).
func validTransformRedirectTo(to string) bool {
	s := strings.ReplaceAll(to, "$uri", "")
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, "//") {
		return false
	}
	if strings.HasPrefix(s, "/") {
		return true
	}
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		u, err := url.Parse(s)
		return err == nil && u.Host != ""
	}
	return false
}

type TransformGet struct {
	Project  string `json:"project" yaml:"project"`
	Location string `json:"location" yaml:"location"`
}

func (m *TransformGet) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Location != "", "location required")

	return WrapValidate(v)
}

// TransformSet upserts the project's transform zone, replacing the whole rule
// set. Mirrors parapet's all-or-nothing reload: one bad rule rejects the batch
// and the previous good set stays live.
type TransformSet struct {
	Project     string          `json:"project" yaml:"project"`
	Location    string          `json:"location" yaml:"location"`
	Description string          `json:"description" yaml:"description"`
	Transforms  []TransformRule `json:"transforms" yaml:"transforms"`
}

func (m *TransformSet) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Location != "", "location required")
	validTransformRules(v, m.Transforms)

	return WrapValidate(v)
}

type TransformDelete struct {
	Project  string `json:"project" yaml:"project"`
	Location string `json:"location" yaml:"location"`
}

func (m *TransformDelete) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Location != "", "location required")

	return WrapValidate(v)
}

type TransformList struct {
	Project string `json:"project" yaml:"project"`
}

func (m *TransformList) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")

	return WrapValidate(v)
}

type TransformListResult struct {
	Project string           `json:"project" yaml:"project"`
	Items   []*TransformItem `json:"items" yaml:"items"`
}

func (m *TransformListResult) Table() [][]string {
	table := [][]string{
		{"LOCATION", "TRANSFORMS", "STATUS", "AGE"},
	}
	for _, x := range m.Items {
		table = append(table, []string{
			x.Location,
			strconv.Itoa(len(x.Transforms)),
			x.Status.Text(),
			age(x.CreatedAt),
		})
	}
	return table
}

type TransformItem struct {
	Project     string          `json:"project" yaml:"project"`
	Location    string          `json:"location" yaml:"location"`
	Description string          `json:"description" yaml:"description"`
	Transforms  []TransformRule `json:"transforms" yaml:"transforms"`
	// Status and Action expose the materialization state: Status is Pending
	// while the deployer is (un)applying the zone and Success once live; Action
	// is Create (set) or Delete (tearing down). Both are read-only.
	Status    Status    `json:"status" yaml:"status"`
	Action    Action    `json:"action" yaml:"action"`
	CreatedAt time.Time `json:"createdAt" yaml:"createdAt"`
	CreatedBy string    `json:"createdBy" yaml:"createdBy"`
}

func (m *TransformItem) Table() [][]string {
	table := [][]string{
		{"PROJECT", "LOCATION", "TRANSFORMS", "STATUS", "AGE"},
		{
			m.Project,
			m.Location,
			strconv.Itoa(len(m.Transforms)),
			m.Status.Text(),
			age(m.CreatedAt),
		},
	}
	return table
}
