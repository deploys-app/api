package api

import (
	"context"
	"time"

	"github.com/moonrhythm/validator"
)

type Location interface {
	// List requires authentication only when a project is supplied (project membership, or platform admin); public locations otherwise (no permission).
	List(ctx context.Context, m *LocationList) (*LocationListResult, error)
	// Get requires no authentication (public location lookup).
	Get(ctx context.Context, m *LocationGet) (*LocationItem, error)
}

type LocationList struct {
	Project string `json:"project" yaml:"project"` // optional
}

type LocationListResult struct {
	Items []*LocationItem `json:"items" yaml:"items"`
}

func (m *LocationListResult) Table() [][]string {
	table := [][]string{
		{"ID", "DOMAIN SUFFIX", "ENDPOINT", "CNAME"},
	}
	for _, x := range m.Items {
		table = append(table, []string{
			x.ID,
			x.DomainSuffix,
			x.Endpoint,
			x.CName,
		})
	}
	return table
}

type LocationItem struct {
	ID                string           `json:"id" yaml:"id"`
	DomainSuffix      string           `json:"domainSuffix" yaml:"domainSuffix"`
	Endpoint          string           `json:"endpoint" yaml:"endpoint"`
	CName             string           `json:"cname" yaml:"cname"`
	FreeTier          bool             `json:"freeTier" yaml:"freeTier"`
	CPUAllocatable    []string         `json:"cpuAllocatable" yaml:"cpuAllocatable"`
	MemoryAllocatable []string         `json:"memoryAllocatable" yaml:"memoryAllocatable"`
	Features          LocationFeatures `json:"features" yaml:"features"`
	CreatedAt         time.Time        `json:"createdAt" yaml:"createdAt"`
}

func (m *LocationItem) Table() [][]string {
	table := [][]string{
		{"ID", "DOMAIN SUFFIX", "ENDPOINT", "CNAME"},
		{
			m.ID,
			m.DomainSuffix,
			m.Endpoint,
			m.CName,
		},
	}
	return table
}

type LocationFeatures struct {
	WorkloadIdentity bool      `json:"workloadIdentity,omitempty" yaml:"workloadIdentity"`
	Disk             *struct{} `json:"disk,omitempty" yaml:"disk"`
	WAF              *struct{} `json:"waf,omitempty" yaml:"waf"`
	// Cache gates the edge cache-override feature (cache.* RPCs). It is EDGE-only
	// and independent of WAF: enable it only for locations whose edge control
	// plane runs CP_CACHE_ENABLED (the apiserver cannot verify edge readiness, so
	// the flag is the human contract that the edge is watching cache ConfigMaps).
	Cache *struct{} `json:"cache,omitempty" yaml:"cache"`
}

type LocationGet struct {
	ID string `json:"id" yaml:"id"`
}

func (m *LocationGet) Valid() error {
	v := validator.New()
	v.Must(m.ID != "", "id required")
	return WrapValidate(v)
}
