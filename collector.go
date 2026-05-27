package api

import (
	"context"
)

type Collector interface {
	Location(ctx context.Context, m *CollectorLocation) (*CollectorLocationResult, error)
	SetProjectUsage(ctx context.Context, m *CollectorSetProjectUsage) (*Empty, error)
	SetDeploymentUsage(ctx context.Context, m *CollectorSetDeploymentUsage) (*Empty, error)
	SetDiskUsage(ctx context.Context, m *CollectorSetDiskUsage) (*Empty, error)
	SetWAFUsage(ctx context.Context, m *CollectorSetWAFUsage) (*Empty, error)
}

type CollectorLocation struct {
	Location string `json:"location" yaml:"location"`
}

type CollectorLocationResult struct {
	Projects []*CollectorProject `json:"projects" yaml:"projects"`
}

type CollectorProject struct {
	ID int64 `json:"id,string" yaml:"id"`
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
