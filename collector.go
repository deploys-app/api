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
