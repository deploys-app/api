package api

import (
	"context"
)

type Collector interface {
	// Location requires the location's collector token (internal endpoint authenticated by the per-location collector_token, not a user permission).
	Location(ctx context.Context, m *CollectorLocation) (*CollectorLocationResult, error)
	// SetProjectUsage requires the location's collector token (internal endpoint authenticated by the per-location collector_token, not a user permission).
	SetProjectUsage(ctx context.Context, m *CollectorSetProjectUsage) (*Empty, error)
	// SetDeploymentUsage requires the location's collector token (internal endpoint authenticated by the per-location collector_token, not a user permission).
	SetDeploymentUsage(ctx context.Context, m *CollectorSetDeploymentUsage) (*Empty, error)
	// SetDiskUsage requires the location's collector token (internal endpoint authenticated by the per-location collector_token, not a user permission).
	SetDiskUsage(ctx context.Context, m *CollectorSetDiskUsage) (*Empty, error)
	// SetWAFUsage requires the location's collector token (internal endpoint authenticated by the per-location collector_token, not a user permission).
	SetWAFUsage(ctx context.Context, m *CollectorSetWAFUsage) (*Empty, error)
	// SetRateLimitUsage requires the location's collector token (internal endpoint authenticated by the per-location collector_token, not a user permission).
	SetRateLimitUsage(ctx context.Context, m *CollectorSetRateLimitUsage) (*Empty, error)
	// SetCacheOverrideUsage requires the location's collector token (internal endpoint authenticated by the per-location collector_token, not a user permission).
	SetCacheOverrideUsage(ctx context.Context, m *CollectorSetCacheOverrideUsage) (*Empty, error)
	// SetCacheResultUsage requires the location's collector token (internal endpoint authenticated by the per-location collector_token, not a user permission).
	SetCacheResultUsage(ctx context.Context, m *CollectorSetCacheResultUsage) (*Empty, error)
	// SetWAFEvents requires the location's collector token (internal endpoint authenticated by the per-location collector_token, not a user permission).
	SetWAFEvents(ctx context.Context, m *CollectorSetWAFEvents) (*Empty, error)
}

type CollectorLocation struct {
	Location string `json:"location" yaml:"location"`
}

type CollectorLocationResult struct {
	Projects []*CollectorProject `json:"projects" yaml:"projects"`
}

type CollectorProject struct {
	ID int64 `json:"id,string" yaml:"id"`

	// SID is the project's string id (e.g. "acme"). The collector uses it to
	// attribute static-gateway request metrics — which are labeled by project
	// SID, not numeric id — back to the numeric project id.
	SID string `json:"sid" yaml:"sid"`

	// Domains are the hostnames routed to this project in the requested
	// location (from the routes table; wildcard domains keep their "*." prefix).
	// The collector uses them to attribute edge cache egress (per-host
	// Prometheus series) back to the project.
	Domains []string `json:"domains" yaml:"domains"`
}

type CollectorSetProjectUsage struct {
	Location  string                                 `json:"location" yaml:"location"`
	ProjectID int64                                  `json:"projectId,string" yaml:"projectId"`
	At        string                                 `json:"at" yaml:"at"`
	Resources []*CollectorProjectUsageResource       `json:"resources" yaml:"resources"`
	Detail    []*CollectorProjectUsageDetailResource `json:"detail" yaml:"detail"`
}

type CollectorProjectUsageResource struct {
	Name  string `json:"name" yaml:"name"`
	Value string `json:"value" yaml:"value"` // decimal
}

type CollectorProjectUsageDetailResource struct {
	Ref   string `json:"ref" yaml:"ref"` // deployment/{name}, disk/{name}
	Name  string `json:"name" yaml:"name"`
	Value string `json:"value" yaml:"value"` // decimal
}

type CollectorSetDeploymentUsage struct {
	Location string                          `json:"location" yaml:"location"`
	List     []*CollectorDeploymentUsageItem `json:"list" yaml:"list"`
}

type CollectorDeploymentUsageItem struct {
	ProjectID      int64   `json:"projectId,string" yaml:"projectId"`
	DeploymentName string  `json:"deploymentName" yaml:"deploymentName"`
	Pod            string  `json:"pod" yaml:"pod"`
	Name           string  `json:"name" yaml:"name"`
	Value          float64 `json:"value" yaml:"value"`
	At             int64   `json:"at" yaml:"at"`
}

type CollectorSetDiskUsage struct {
	Location string                    `json:"location" yaml:"location"`
	List     []*CollectorDiskUsageItem `json:"list" yaml:"list"`
}

type CollectorDiskUsageItem struct {
	ProjectID int64   `json:"projectId,string" yaml:"projectId"`
	DiskName  string  `json:"diskName" yaml:"diskName"`
	Name      string  `json:"name" yaml:"name"`
	Value     float64 `json:"value" yaml:"value"`
	At        int64   `json:"at" yaml:"at"`
}

// CollectorSetWAFUsage upserts WAF match counts collected from parapet's
// parapet_waf_matches counter. Each item is one (rule_id, action) bucket for a
// minute; the collector parses ProjectID from the project-prefixed RuleID
// (<projectID>-<rand>). Upserted by (location, project, ruleId, action, at) so
// back-fill re-runs are idempotent.
type CollectorSetWAFUsage struct {
	Location string                   `json:"location" yaml:"location"`
	List     []*CollectorWAFUsageItem `json:"list" yaml:"list"`
}

type CollectorWAFUsageItem struct {
	ProjectID int64   `json:"projectId,string" yaml:"projectId"`
	RuleID    string  `json:"ruleId" yaml:"ruleId"` // full generated id (<projectID>-<rand>)
	Action    string  `json:"action" yaml:"action"` // log|allow|block
	Value     float64 `json:"value" yaml:"value"`   // match count in the window
	At        int64   `json:"at" yaml:"at"`         // unix second, minute-aligned bucket
}

// CollectorSetRateLimitUsage upserts zone rate-limit decision counts collected
// from parapet's parapet_ratelimit_total counter. Each item is one
// (limit_id, result) bucket for a minute; the collector parses ProjectID from
// the project-prefixed LimitID (<projectID>-<rand>, the same scheme as WAF
// rule ids). Upserted by (location, project, limitId, result, at) so
// back-fill re-runs are idempotent.
type CollectorSetRateLimitUsage struct {
	Location string                         `json:"location" yaml:"location"`
	List     []*CollectorRateLimitUsageItem `json:"list" yaml:"list"`
}

type CollectorRateLimitUsageItem struct {
	ProjectID int64   `json:"projectId,string" yaml:"projectId"`
	LimitID   string  `json:"limitId" yaml:"limitId"` // full generated id (<projectID>-<rand>)
	Result    string  `json:"result" yaml:"result"`   // allowed|limited
	Value     float64 `json:"value" yaml:"value"`     // decision count in the window
	At        int64   `json:"at" yaml:"at"`           // unix second, minute-aligned bucket
}

// CollectorSetCacheOverrideUsage upserts cache-override decision counts
// collected from parapet's parapet_cache_override_total counter. Each item is
// one (override_id, action, result) bucket for a minute; the collector parses
// ProjectID from the project-prefixed OverrideID (<projectID>-<rand>, the same
// scheme as WAF rule ids). Upserted by (location, project, overrideId, action,
// result, at) so back-fill re-runs are idempotent. The vec carries BOTH action
// and result, so both are part of the bucket (unlike WAF action-only / rate
// limit result-only).
type CollectorSetCacheOverrideUsage struct {
	Location string                             `json:"location" yaml:"location"`
	List     []*CollectorCacheOverrideUsageItem `json:"list" yaml:"list"`
}

type CollectorCacheOverrideUsageItem struct {
	ProjectID  int64   `json:"projectId,string" yaml:"projectId"`
	OverrideID string  `json:"overrideId" yaml:"overrideId"` // full generated id (<projectID>-<rand>)
	Action     string  `json:"action" yaml:"action"`         // cache|bypass
	Result     string  `json:"result" yaml:"result"`         // applied|shadow|error
	Value      float64 `json:"value" yaml:"value"`           // decision count in the window
	At         int64   `json:"at" yaml:"at"`                 // unix second, minute-aligned bucket
}

// CollectorSetCacheResultUsage upserts edge response-cache outcome counts
// collected from parapet's parapet_cache_total (requests) and
// parapet_cache_egress_bytes (bytes) counters. Each item is one (project,
// result) bucket for a minute, attributed to ProjectID by the request Host
// (resolved via the location's routed domains, like cache egress). Result is
// normalized to HIT/MISS/STALE/BYPASS (STALE_ERROR is folded into STALE).
// Upserted by (location, project, result, at) so back-fill re-runs are
// idempotent. Requests/Bytes are independent — a bucket may carry one without
// the other (BYPASS has requests but no cache-egress bytes).
type CollectorSetCacheResultUsage struct {
	Location string                           `json:"location" yaml:"location"`
	List     []*CollectorCacheResultUsageItem `json:"list" yaml:"list"`
}

type CollectorCacheResultUsageItem struct {
	ProjectID int64   `json:"projectId,string" yaml:"projectId"`
	Result    string  `json:"result" yaml:"result"`     // HIT|MISS|STALE|BYPASS
	Requests  float64 `json:"requests" yaml:"requests"` // request count in the window
	Bytes     float64 `json:"bytes" yaml:"bytes"`       // bytes served in the window
	At        int64   `json:"at" yaml:"at"`             // unix second, minute-aligned bucket
}

// CollectorSetWAFEvents appends sampled WAF match events captured from the
// controller's event ring (SPEC-waf-events). Items are deduplicated by ID
// (the controller-minted ULID), so at-least-once shipping after cursor loss
// is safe. ProjectID is parsed by the collector from the project-prefixed
// RuleID (<projectID>-<rand>), exactly like CollectorSetWAFUsage; the server
// re-checks the pairing against the rule-id prefix before storing.
//
// Unlike the usage setters this RPC is synchronous server-side: events have
// no healing second source (usage loops re-query Prometheus, the event ring
// is drained), so a failed insert must surface as an error and the collector
// must advance its per-pod ring cursor only after a successful call.
type CollectorSetWAFEvents struct {
	Location string                   `json:"location" yaml:"location"`
	List     []*CollectorWAFEventItem `json:"list" yaml:"list"`
}

type CollectorWAFEventItem struct {
	ID        string `json:"id" yaml:"id"` // controller ULID, dedupe key
	ProjectID int64  `json:"projectId,string" yaml:"projectId"`
	RuleID    string `json:"ruleId" yaml:"ruleId"` // full generated id (<projectID>-<rand>)
	Action    string `json:"action" yaml:"action"` // log|allow|block
	Status    int    `json:"status" yaml:"status"`
	At        int64  `json:"at" yaml:"at"` // unix second (event time at the engine)
	ClientIP  string `json:"clientIp" yaml:"clientIp"`
	Country   string `json:"country" yaml:"country"` // ISO 3166-1 alpha-2, "" if unresolved
	ASN       int64  `json:"asn" yaml:"asn"`         // 0 if unresolved
	Method    string `json:"method" yaml:"method"`
	Host      string `json:"host" yaml:"host"`
	Path      string `json:"path" yaml:"path"` // URL path only (no query)
}
