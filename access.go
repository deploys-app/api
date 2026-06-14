package api

import (
	"context"

	"github.com/moonrhythm/validator"
)

// Access is an internal/privileged interface used by the access verifier
// service (access.deploys.app) to fetch a deployment's access policy. Like
// Collector and Deployer, it is authenticated by a shared internal secret, not
// a user permission.
type Access interface {
	// Policy returns the deployment's access policy for the verifier to
	// enforce. Requires the internal access secret. An unknown deployment
	// returns ErrDeploymentNotFound, which the verifier treats as deny.
	Policy(ctx context.Context, m *AccessPolicy) (*AccessPolicyResult, error)
}

type AccessPolicy struct {
	DeploymentID int64 `json:"deploymentId,string" yaml:"deploymentId"`
}

func (m *AccessPolicy) Valid() error {
	v := validator.New()
	v.Must(m.DeploymentID > 0, "deploymentId required")
	return WrapValidate(v)
}

// AccessPolicyResult is a deployment's effective access policy. RequireGoogleLogin
// false means the deployment is public. Empty AllowedEmails AND AllowedDomains
// with RequireGoogleLogin true means any signed-in Google account.
type AccessPolicyResult struct {
	RequireGoogleLogin bool     `json:"requireGoogleLogin" yaml:"requireGoogleLogin"`
	AllowedEmails      []string `json:"allowedEmails" yaml:"allowedEmails"`
	AllowedDomains     []string `json:"allowedDomains" yaml:"allowedDomains"`
	// Hosts are the deployment's gated hostnames: its default URL plus every
	// custom-domain route that targets it. The verifier uses this as the
	// redirect/handoff allowlist so it will only set a host-only session cookie
	// for a domain that legitimately belongs to this deployment (closing the
	// open-redirect/cookie-injection hole for arbitrary custom domains).
	Hosts []string `json:"hosts" yaml:"hosts"`
}
