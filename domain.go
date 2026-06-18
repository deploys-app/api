package api

import (
	"context"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/moonrhythm/validator"
)

type Domain interface {
	// Create requires the `domain.create` permission.
	Create(ctx context.Context, m *DomainCreate) (*Empty, error)
	// Get requires the `domain.get` permission.
	Get(ctx context.Context, m *DomainGet) (*DomainItem, error)
	// List requires the `domain.list` permission.
	List(ctx context.Context, m *DomainList) (*DomainListResult, error)
	// Delete requires the `domain.delete` permission.
	Delete(ctx context.Context, m *DomainDelete) (*Empty, error)
	// PurgeCache requires the `domain.purgecache` permission.
	PurgeCache(ctx context.Context, m *DomainPurgeCache) (*Empty, error)
}

type DomainCreate struct {
	Project  string `json:"project" yaml:"project"`
	Location string `json:"location" yaml:"location"`
	Domain   string `json:"domain" yaml:"domain"`
	Wildcard bool   `json:"wildcard" yaml:"wildcard"`
}

func (m *DomainCreate) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Location != "", "location required")
	v.Must(govalidator.IsDNSName(m.Domain), "domain invalid")
	v.Must(!strings.HasSuffix(m.Domain, ".deploys.app"), "domain invalid")

	return WrapValidate(v)
}

type DomainGet struct {
	Project string `json:"project" yaml:"project"`
	Domain  string `json:"domain" yaml:"domain"`
}

func (m *DomainGet) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(govalidator.IsDNSName(m.Domain), "domain invalid")

	return WrapValidate(v)
}

type DomainList struct {
	Project  string `json:"project" yaml:"project"`
	Location string `json:"location" yaml:"location"`
}

func (m *DomainList) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")

	return WrapValidate(v)
}

type DomainListResult struct {
	Items []*DomainItem `json:"items" yaml:"items"`
}

func (m *DomainListResult) Table() [][]string {
	table := [][]string{
		{"DOMAIN", "LOCATION"},
	}
	for _, x := range m.Items {
		table = append(table, []string{
			x.Domain,
			x.Location,
		})
	}
	return table
}

type DomainItem struct {
	Project      string             `json:"project" yaml:"project"`
	Location     string             `json:"location" yaml:"location"`
	Domain       string             `json:"domain" yaml:"domain"`
	Wildcard     bool               `json:"wildcard" yaml:"wildcard"`
	Verification DomainVerification `json:"verification" yaml:"verification"`
	DNSConfig    DomainDNSConfig    `json:"dnsConfig" yaml:"dnsConfig"`
	Status       DomainStatus       `json:"status" yaml:"status"`
	// CertStatus is the TLS certificate lifecycle state (none / pendingCreate /
	// created / pendingDelete). CertPendingSince is when the cert entered
	// pendingCreate — set only while issuance is outstanding — so the console can
	// show how long a cert has been issuing and warn as it nears the reclaim
	// window. Cleared once the cert issues (created) or is torn down.
	CertStatus       DomainCertStatus `json:"certStatus" yaml:"certStatus"`
	CertPendingSince time.Time        `json:"certPendingSince,omitempty" yaml:"certPendingSince,omitempty"`
	CreatedAt        time.Time        `json:"createdAt" yaml:"createdAt"`
	CreatedBy        string           `json:"createdBy" yaml:"createdBy"`
}

type DomainVerification struct {
	Ownership DomainVerificationOwnership `json:"ownership"`
	SSL       DomainVerificationSSL       `json:"ssl"`
	DNS       DomainVerificationDNS       `json:"dns"`
}

// DomainVerificationDNS is the apiserver's view of the DNS check. Populated by
// the verify-domains cron. VerifiedAt is the last time DNS pointed at the
// location's load balancer (directly or via a proxy with a matching ownership
// TXT). LastCheckedAt is the most recent attempt.
type DomainVerificationDNS struct {
	VerifiedAt    time.Time `json:"verifiedAt,omitempty"`
	LastCheckedAt time.Time `json:"lastCheckedAt,omitempty"`
	Errors        []string  `json:"errors,omitempty"`
}

type DomainVerificationOwnership struct {
	Type   string   `json:"type"`
	Name   string   `json:"name"`
	Value  string   `json:"value"`
	Errors []string `json:"errors"`
}

type DomainVerificationSSL struct {
	Pending bool                          `json:"pending"`
	DCV     DomainVerificationSSLDCV      `json:"dcv"`
	Records []DomainVerificationSSLRecord `json:"records"`
	Errors  []string                      `json:"errors"`
}

type DomainVerificationSSLDCV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type DomainVerificationSSLRecord struct {
	TxtName  string `json:"txtName"`
	TxtValue string `json:"txtValue"`
}

type DomainDNSConfig struct {
	IPv4  []string `json:"ipv4" yaml:"ipv4"`
	IPv6  []string `json:"ipv6" yaml:"ipv6"`
	CName []string `json:"cname" yaml:"cname"`
}

type DomainDelete struct {
	Project string `json:"project" yaml:"project"`
	Domain  string `json:"domain" yaml:"domain"`
}

func (m *DomainDelete) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(govalidator.IsDNSName(m.Domain), "domain invalid")

	return WrapValidate(v)
}

type DomainPurgeCache struct {
	Project string `json:"project" yaml:"project"`
	Domain  string `json:"domain" yaml:"domain"`
	File    string `json:"file" yaml:"file"`
	Prefix  string `json:"prefix" yaml:"prefix"`
}

func (m *DomainPurgeCache) Valid() error {
	v := validator.New()

	m.Domain = strings.TrimSpace(m.Domain)
	m.File = strings.TrimSpace(m.File)
	m.Prefix = strings.TrimSpace(m.Prefix)

	v.Must(m.Project != "", "project required")
	v.Must(govalidator.IsDNSName(m.Domain), "domain invalid")

	return WrapValidate(v)
}
