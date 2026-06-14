package api

import (
	"context"
)

type Deployer interface {
	// GetLocation requires the location's deployer token (internal endpoint authenticated by the per-location deployer_token, not a user permission).
	GetLocation(ctx context.Context, m *Empty) (*LocationItem, error)
	// IsDomainActive requires the location's deployer token (internal endpoint authenticated by the per-location deployer_token, not a user permission).
	IsDomainActive(ctx context.Context, m *DeployerIsDomainActive) (bool, error)
	// GetCommands requires the location's deployer token (internal endpoint authenticated by the per-location deployer_token, not a user permission).
	GetCommands(ctx context.Context, m *Empty) (*GetCommandsResult, error)
	// SetResults requires the location's deployer token (internal endpoint authenticated by the per-location deployer_token, not a user permission).
	SetResults(ctx context.Context, m *DeployerSetResult) (*Empty, error)
}

type DeployerIsDomainActive struct {
	Domain string `json:"domain"`
}

type GetCommandsResult []*DeployerCommandItem

type DeployerCommandItem struct {
	PullSecretCreate       *DeployerCommandPullSecretCreate       `json:"pullSecretCreate,omitempty"`
	PullSecretDelete       *DeployerCommandMetadata               `json:"pullSecretDelete,omitempty"`
	WorkloadIdentityCreate *DeployerCommandWorkloadIdentityCreate `json:"workloadIdentityCreate,omitempty"`
	WorkloadIdentityDelete *DeployerCommandMetadata               `json:"workloadIdentityDelete,omitempty"`
	DiskCreate             *DeployerCommandDiskCreate             `json:"diskCreate,omitempty"`
	DiskDelete             *DeployerCommandMetadata               `json:"diskDelete,omitempty"`
	DeploymentDeploy       *DeployerCommandDeploymentDeploy       `json:"deploymentDeploy,omitempty"`
	DeploymentDelete       *DeployerCommandDeploymentMetadata     `json:"deploymentDelete,omitempty"`
	DeploymentPause        *DeployerCommandDeploymentMetadata     `json:"deploymentPause,omitempty"`
	DeploymentCleanup      *DeployerCommandDeploymentMetadata     `json:"deploymentCleanup,omitempty"`
	RouteCreate            *DeployerCommandRouteCreate            `json:"routeCreate,omitempty"`
	RouteDelete            *DeployerCommandRouteDelete            `json:"routeDelete,omitempty"`
	DomainCertCreate       *DeployerCommandDomainCertCreate       `json:"domainCertCreate,omitempty"`
	DomainCertDelete       *DeployerCommandDomainCertDelete       `json:"domainCertDelete,omitempty"`
	WAFSet                 *DeployerCommandWAFSet                 `json:"wafSet,omitempty"`
	WAFDelete              *DeployerCommandWAFDelete              `json:"wafDelete,omitempty"`
	CacheSet               *DeployerCommandCacheSet               `json:"cacheSet,omitempty"`
	CacheDelete            *DeployerCommandCacheDelete            `json:"cacheDelete,omitempty"`
}

type DeployerCommandMetadata struct {
	ID        int64  `json:"id"`
	ProjectID int64  `json:"projectId"`
	Name      string `json:"name"`
}

type DeployerCommandPullSecretCreate struct {
	ID        int64  `json:"id"`
	ProjectID int64  `json:"projectId"`
	Name      string `json:"name"`
	Value     string `json:"value"`
}

type DeployerCommandWorkloadIdentityCreate struct {
	ID        int64  `json:"id"`
	ProjectID int64  `json:"projectId"`
	Name      string `json:"name"`
	GSA       string `json:"gsa"`
}

type DeployerCommandDiskCreate struct {
	ID        int64  `json:"id"`
	ProjectID int64  `json:"projectId"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
}

type DeployerCommandDeploymentMetadata struct {
	ID        int64          `json:"id"`
	ProjectID int64          `json:"projectId"`
	Name      string         `json:"name"`
	Revision  int64          `json:"revision"`
	Type      DeploymentType `json:"type"`
}

type DeployerCommandDeploymentDeploy struct {
	ID        int64 `json:"id"`
	ProjectID int64 `json:"projectId"`
	// Name is the k8s resource name prefix: the deployer derives every object
	// name from it (<Name>-<ProjectID>). For deployments created before
	// id-based naming it equals the display name; newer deployments use the
	// server-assigned resource name (0d<id>), which can never collide with a
	// display name (display names must start with a letter).
	Name string `json:"name"`
	// DisplayName is the user-facing deployment name, used only for cosmetic
	// surfaces (K_SERVICE/K_CONFIGURATION env, deploys.app/name annotation).
	// Empty on commands from apiservers that predate it — fall back to Name.
	DisplayName   string                                       `json:"displayName"`
	Revision      int64                                        `json:"revision"`
	Type          DeploymentType                               `json:"type"`
	BillingConfig DeployerCommandDeploymentDeployBillingConfig `json:"config"`
	Spec          DeployerCommandDeploymentDeploySpec          `json:"spec"`
}

type DeployerCommandDeploymentDeployBillingConfig struct {
	Pool      string `json:"pool"`
	SharePool bool   `json:"sharePool"`
	ForceSpot bool   `json:"forceSpot"`
}

type DeployerCommandDeploymentDeploySpec struct {
	Image string `json:"image"`
	// Site and SitePrefix carry the static site release: for Static deployments
	// Image is empty and these point the deployer at the served release.
	Site                 string                  `json:"site"`
	SitePrefix           string                  `json:"sitePrefix"`
	Env                  map[string]string       `json:"env"`
	Command              []string                `json:"command"`
	Args                 []string                `json:"args"`
	WorkloadIdentityName string                  `json:"workloadIdentityName"`
	MinReplicas          int                     `json:"minReplicas"`
	MaxReplicas          int                     `json:"maxReplicas"`
	Port                 int                     `json:"port"`
	Protocol             DeploymentProtocol      `json:"protocol"`
	Internal             bool                    `json:"internal"`
	Schedule             string                  `json:"schedule"`
	Annotations          map[string]string       `json:"annotations"`
	CPU                  string                  `json:"cpu"`
	CPULimit             string                  `json:"cpuLimit"`
	Memory               string                  `json:"memory"`
	PullSecretName       string                  `json:"pullSecretName"`
	DiskName             string                  `json:"diskName"`
	DiskMountPath        string                  `json:"diskMountPath"`
	DiskSubPath          string                  `json:"diskSubPath"`
	MountData            map[string]string       `json:"mountData"` // file path => data
	Sidecars             []*Sidecar              `json:"sidecars"`
	HealthCheck          DeploymentHealthCheck   `json:"healthCheck"`
	Access               *DeploymentAccessConfig `json:"access"`
}

type DeploymentHealthCheck struct {
	TCPSocket *TCPSocketAction `json:"tcpSocket"`
	HTTPGet   *HTTPGetAction   `json:"httpGet"`
}

type TCPSocketAction struct{}

type HTTPGetAction struct {
	Path string `json:"path"`
}

type DeployerCommandRouteCreate struct {
	ID        int64  `json:"id"`
	ProjectID int64  `json:"projectId"`
	Domain    string `json:"domain"`
	Path      string `json:"path"`
	Target    string `json:"target"`
	// TargetType is set for deployment:// targets so the deployer can tell a
	// Static target from a container (WebService) one. Static deployments have
	// no per-deployment Service — they are served by the shared static-gateway —
	// so the deployer must back the ingress with static-gateway + SitePrefix
	// instead of a per-deployment Service. Empty for non-deployment targets.
	TargetType DeploymentType `json:"targetType"`
	// SitePrefix is set only when TargetType is DeploymentTypeStatic: the
	// release prefix "<project>/<name>/<release-sha>" the static-gateway uses to
	// locate the release in object storage (carried in the ingress upstream-path,
	// mirroring the static deployment's default-URL ingress).
	SitePrefix string      `json:"sitePrefix"`
	Config     RouteConfig `json:"config"`
}

type DeployerCommandRouteDelete struct {
	ID        int64  `json:"id"`
	ProjectID int64  `json:"projectId"`
	Domain    string `json:"domain"`
}

// DeployerCommandDomainCertCreate asks the location's deployer to issue a
// cert-manager Certificate for a non-CDN domain that has passed DNS
// verification. Issued by the apiserver when domains.cert_status transitions
// to DomainCertStatusPendingCreate.
//
// Wildcard rows route through a different cert-manager ClusterIssuer (DNS-01
// via Cloud DNS + CNAME delegation) because Let's Encrypt requires DNS-01 for
// `*.example.com`. The deployer branches on Wildcard to pick the issuer and
// SAN list.
type DeployerCommandDomainCertCreate struct {
	ID        int64  `json:"id"`
	ProjectID int64  `json:"projectId"`
	Domain    string `json:"domain"`
	Wildcard  bool   `json:"wildcard"`
}

// DeployerCommandDomainCertDelete asks the location's deployer to remove the
// cert-manager Certificate for a non-CDN domain whose DNS no longer points at
// us (or that's being deleted). Issued when cert_status transitions to
// DomainCertStatusPendingDelete.
type DeployerCommandDomainCertDelete struct {
	ID        int64  `json:"id"`
	ProjectID int64  `json:"projectId"`
	Domain    string `json:"domain"`
}

// DeployerCommandWAFSet asks the location's deployer to materialize the
// project's WAF zone: upsert a parapet zone ConfigMap (name = ZoneID, labeled
// parapet.moonrhythm.io/waf: zone) holding the rules, and bind every one of the
// project's Ingresses in this location via the parapet.moonrhythm.io/waf-zone
// annotation. Issued when waf_zones.action is Create or Update.
//
// Limits materialize the same way into a separate parapet ratelimit zone
// ConfigMap (name = RateLimitZoneID, labeled parapet.moonrhythm.io/ratelimit:
// zone) bound via the parapet.moonrhythm.io/ratelimit-zone annotation. An
// empty Limits removes that ConfigMap and annotation, so the parapet
// controller drops the zone entirely instead of keeping an empty set.
type DeployerCommandWAFSet struct {
	ID              int64      `json:"id"`
	ProjectID       int64      `json:"projectId"`
	ZoneID          string     `json:"zoneId"`
	RateLimitZoneID string     `json:"rateLimitZoneId"`
	Rules           []WAFRule  `json:"rules"`
	Limits          []WAFLimit `json:"limits"`
}

// DeployerCommandWAFDelete asks the location's deployer to remove the project's
// WAF zone and ratelimit zone ConfigMaps and strip the waf-zone/ratelimit-zone
// annotations from its Ingresses. Issued when waf_zones.action is Delete.
type DeployerCommandWAFDelete struct {
	ID              int64  `json:"id"`
	ProjectID       int64  `json:"projectId"`
	ZoneID          string `json:"zoneId"`
	RateLimitZoneID string `json:"rateLimitZoneId"`
}

// DeployerCommandCacheSet asks the location's deployer to materialize the
// project's cache-override zone: upsert a parapet cache zone ConfigMap (name =
// ZoneID, labeled parapet.moonrhythm.io/cache: zone) holding the overrides, and
// bind every one of the project's Ingresses in this location via the
// parapet.moonrhythm.io/cache-zone annotation. Issued when cache_zones.action
// is Create or Update.
//
// Unlike WAF there is a single ZoneID (cache is one ConfigMap; there is no
// separate ratelimit-style sibling). Cache overrides are edge-only — only the
// edge control plane consumes the ConfigMap and annotation.
type DeployerCommandCacheSet struct {
	ID        int64           `json:"id"`
	ProjectID int64           `json:"projectId"`
	ZoneID    string          `json:"zoneId"`
	Overrides []CacheOverride `json:"overrides"`
}

// DeployerCommandCacheDelete asks the location's deployer to remove the
// project's cache zone ConfigMap and strip the cache-zone annotation from its
// Ingresses. Issued when cache_zones.action is Delete.
type DeployerCommandCacheDelete struct {
	ID        int64  `json:"id"`
	ProjectID int64  `json:"projectId"`
	ZoneID    string `json:"zoneId"`
}

type DeployerSetResult []*DeployerSetResultItem

type DeployerSetResultItem struct {
	PullSecretCreate       *DeployerSetResultItemGeneral    `json:"pullSecretCreate,omitempty"`
	PullSecretDelete       *DeployerSetResultItemGeneral    `json:"pullSecretDelete,omitempty"`
	WorkloadIdentityCreate *DeployerSetResultItemGeneral    `json:"workloadIdentityCreate,omitempty"`
	WorkloadIdentityDelete *DeployerSetResultItemGeneral    `json:"workloadIdentityDelete,omitempty"`
	DiskCreate             *DeployerSetResultItemGeneral    `json:"diskCreate,omitempty"`
	DiskDelete             *DeployerSetResultItemGeneral    `json:"diskDelete,omitempty"`
	DeploymentDeploy       *DeployerSetResultItemDeploy     `json:"deploymentDeploy,omitempty"`
	DeploymentDelete       *DeployerSetResultItemGeneral    `json:"deploymentDelete,omitempty"`
	DeploymentPause        *DeployerSetResultItemDeployment `json:"deploymentPause,omitempty"`
	DeploymentCleanup      *DeployerSetResultItemDeployment `json:"deploymentCleanup,omitempty"`
	RouteCreate            *DeployerSetResultItemGeneral    `json:"routeCreate,omitempty"`
	RouteDelete            *DeployerSetResultItemGeneral    `json:"routeDelete,omitempty"`
	DomainCertCreate       *DeployerSetResultItemGeneral    `json:"domainCertCreate,omitempty"`
	DomainCertDelete       *DeployerSetResultItemGeneral    `json:"domainCertDelete,omitempty"`
	WAFSet                 *DeployerSetResultItemGeneral    `json:"wafSet,omitempty"`
	WAFDelete              *DeployerSetResultItemGeneral    `json:"wafDelete,omitempty"`
	CacheSet               *DeployerSetResultItemGeneral    `json:"cacheSet,omitempty"`
	CacheDelete            *DeployerSetResultItemGeneral    `json:"cacheDelete,omitempty"`
}

type DeployerSetResultItemGeneral struct {
	ID int64 `json:"id"`
}

type DeployerSetResultItemDeploy struct {
	ID       int64 `json:"id"`
	Revision int64 `json:"revision"`
	Success  bool  `json:"success"`
	NodePort *int  `json:"nodePort,omitempty"`
}

type DeployerSetResultItemDeployment struct {
	ID       int64 `json:"id"`
	Revision int64 `json:"revision"`
}
