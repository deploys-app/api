package api

import (
	"context"
	"time"
)

type Dropbox interface {
	List(ctx context.Context, m *DropboxList) (*DropboxListResult, error)
}

type DropboxList struct {
	Project string    `json:"project" yaml:"project"`
	After   time.Time `json:"after" yaml:"after"`
	Before  time.Time `json:"before" yaml:"before"`
	Limit   int       `json:"limit" yaml:"limit"`
}

func (m *DropboxList) Valid() error {
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

type DropboxListResult struct {
	Items []*DropboxItem `json:"items" yaml:"items"`
}

type DropboxItem struct {
	Fn        string    `json:"fn" yaml:"fn"`
	Filename  string    `json:"filename" yaml:"filename"`
	Size      int64     `json:"size" yaml:"size"`
	TTL       int       `json:"ttl" yaml:"ttl"`
	CreatedAt time.Time `json:"createdAt" yaml:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt" yaml:"expiresAt"`
}
