package api

import (
	"regexp"
	"time"
)

const (
	ReValidNameStr      = `^[a-z][a-z0-9\-]*[a-z0-9]$`
	ReValidScheduleStr  = `^((((\*(/\d+)?)|(\d+((-\d+)|(/\d+))?)),?)+\s?){5}$`
	ReValidWAFRuleIDStr = `^[a-zA-Z0-9][a-zA-Z0-9_\-]*$`
)

// global
var (
	ReValidName      = regexp.MustCompile(ReValidNameStr)
	ReValidSchedule  = regexp.MustCompile(ReValidScheduleStr)
	ReValidWAFRuleID = regexp.MustCompile(ReValidWAFRuleIDStr)
)

// global
const (
	MinNameLength = 3
	MaxNameLength = 26
)

// Deployments
const (
	DeploymentMinReplicas = 1
	DeploymentMaxReplicas = 20
	DiskMaxSize           = 100

	// DeploymentMaxNameLength is the deployment-specific name cap. Deployment
	// names are display names only — k8s objects are named by the deployment's
	// server-assigned resource name (0d<id>), so the name no longer has to fit
	// k8s DNS-label budgets like other resources (which keep MaxNameLength).
	DeploymentMaxNameLength = 63
)

// WAF
const (
	WAFMaxRules            = 100
	WAFMaxRuleIDLength     = 64
	WAFMaxExpressionLength = 2048
	WAFMaxMessageLength    = 256

	// Rate limits (parapet ratelimitrule): limit ids label parapet metric
	// series, so parapet caps them at 63 chars; the window bounds mirror
	// parapet's 1s..1h cap on per-key counter retention.
	WAFMaxLimits        = 20
	WAFMaxLimitIDLength = 63
	WAFLimitMinWindow   = time.Second
	WAFLimitMaxWindow   = time.Hour
)

// Cache overrides (parapet cacherule)
const (
	CacheMaxOverrides = 50

	// CacheMaxOverrideIDLength matches parapet's hard 63-char cap on an override
	// id (override ids label parapet_cache_override_total series). NOTE the cap
	// is on the FULL stored id (<projectID>-<rand>), so the server must validate
	// the prefixed form, not just the client-facing short id.
	CacheMaxOverrideIDLength = 63

	// CacheMaxFilterLength caps the CEL filter; it shares the WAF expression
	// surface so it uses the same budget.
	CacheMaxFilterLength = WAFMaxExpressionLength

	// CacheMinTTL mirrors parapet's 1s minimum forced freshness lifetime;
	// CacheMaxTTL is a deploys.app policy cap (parapet itself sets no upper
	// bound).
	CacheMinTTL = time.Second
	CacheMaxTTL = 720 * time.Hour
)

// Scheduler (scheduled HTTP requests)
const (
	SchedulerMaxHeaders           = 50
	SchedulerMaxHeaderKeyLength   = 256
	SchedulerMaxHeaderValueLength = 8192
	SchedulerMaxURLLength         = 2048
	SchedulerMaxBodySize          = 64 * 1024 // 64 KiB

	SchedulerDefaultLogLimit = 50
	SchedulerMaxLogLimit     = 100

	// SchedulerDefaultUserAgent is sent on every scheduled request unless the job
	// overrides it via a custom "User-Agent" header. It is the value the platform
	// WAF global baseline allowlists so scheduled requests aren't blocked.
	SchedulerDefaultUserAgent = "deploys-scheduler/1.0"

	// SchedulerRequestTimeout bounds a single outbound scheduled request so a slow
	// target can't stall the tick. Not user-configurable in v1.
	SchedulerRequestTimeout = 30 * time.Second
)
