package api

import (
	"context"
	"time"
)

type AuditLog interface {
	List(ctx context.Context, m *AuditLogList) (*AuditLogListResult, error)
}

type AuditLogActor struct {
	Email string         `json:"email" yaml:"email"`
	Type  AuditActorType `json:"type" yaml:"type"`
}

type AuditLogResource struct {
	Type       string `json:"type" yaml:"type"`
	ID         string `json:"id" yaml:"id"`
	Name       string `json:"name" yaml:"name"`
	LocationID string `json:"locationId" yaml:"locationId"`
}

type AuditLogItem struct {
	ID        int64            `json:"id" yaml:"id"`
	Resource  AuditLogResource `json:"resource" yaml:"resource"`
	Actor     AuditLogActor    `json:"actor" yaml:"actor"`
	Action    string           `json:"action" yaml:"action"`
	Outcome   AuditOutcome     `json:"outcome" yaml:"outcome"`
	Detail    string           `json:"detail" yaml:"detail"`
	CreatedAt time.Time        `json:"createdAt" yaml:"createdAt"`
}

type AuditLogListResult struct {
	Items []*AuditLogItem `json:"items" yaml:"items"`
}

type AuditLogList struct {
	Project      string    `json:"project" yaml:"project"`
	ResourceType string    `json:"resourceType" yaml:"resourceType"`
	Actor        string    `json:"actor" yaml:"actor"`
	Outcome      int       `json:"outcome" yaml:"outcome"`
	After        time.Time `json:"after" yaml:"after"`
	Before       time.Time `json:"before" yaml:"before"`
	Limit        int       `json:"limit" yaml:"limit"`
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
