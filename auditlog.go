package api

import (
	"context"
	"time"
)

type AuditLog interface {
	List(ctx context.Context, m *AuditLogList) (*AuditLogListResult, error)
}

type AuditLogList struct {
	Project      string `json:"project" yaml:"project"`
	ResourceType string `json:"resourceType" yaml:"resourceType"`
	Actor        string `json:"actor" yaml:"actor"`
	Outcome      int    `json:"outcome" yaml:"outcome"`
	Before       int64  `json:"before" yaml:"before"`
	Limit        int    `json:"limit" yaml:"limit"`
}

func (m *AuditLogList) Valid() error {
	if m.Project == "" {
		return newError("project required")
	}
	if m.Limit <= 0 {
		m.Limit = 50
	}
	if m.Limit > 100 {
		m.Limit = 100
	}
	return nil
}

type AuditLogItem struct {
	ID           int64     `json:"id" yaml:"id"`
	ResourceType string    `json:"resourceType" yaml:"resourceType"`
	ResourceID   string    `json:"resourceId" yaml:"resourceId"`
	ResourceName string    `json:"resourceName" yaml:"resourceName"`
	Action       string    `json:"action" yaml:"action"`
	Actor        string    `json:"actor" yaml:"actor"`
	ActorType    int       `json:"actorType" yaml:"actorType"`
	LocationID   string    `json:"locationId" yaml:"locationId"`
	Outcome      int       `json:"outcome" yaml:"outcome"`
	Detail       string    `json:"detail" yaml:"detail"`
	CreatedAt    time.Time `json:"createdAt" yaml:"createdAt"`
}

type AuditLogListResult struct {
	Items []*AuditLogItem `json:"items" yaml:"items"`
}
