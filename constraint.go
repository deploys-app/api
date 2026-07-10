package api

import (
	"regexp"
	"time"
)

const (
	ReValidNameStr      = `^[a-z][a-z0-9\-]*[a-z0-9]$`
	ReValidScheduleStr  = `^((((\*(/\d+)?)|(\d+((-\d+)|(/\d+))?)),?)+\s?){5}$`
	ReValidWAFRuleIDStr = `^[a-zA-Z0-9][a-zA-Z0-9_\-]*$`

	// ReValidNameDesc is a plain-English description of ReValidNameStr, shown to
	// users in validation errors instead of the raw regexp (which most people
	// can't read).
	ReValidNameDesc = "use lowercase letters, numbers, and hyphens, starting with a letter and ending with a letter or number"
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

// Deployment logs (deployment.logs bounded snapshot)
const (
	// DeploymentLogsDefaultTailLines is the per-pod line count used when the
	// request leaves TailLines unset (token-cheap default).
	DeploymentLogsDefaultTailLines = 200
	// DeploymentLogsMaxTailLines clamps the per-pod line count. k8s applies
	// TailLines per container, so a deployment with N pods can still return up
	// to TailLines×N lines — the server's byte budget is the real cap.
	DeploymentLogsMaxTailLines = 1000
)

// Deployment logs history (deployment.logsHistory durable retrieval)
const (
	// DeploymentLogsHistoryDefaultLimit is the page size used when Limit is unset.
	DeploymentLogsHistoryDefaultLimit = 200
	// DeploymentLogsHistoryMaxLimit clamps the page size; the server byte budget
	// is the real per-page cap, and NextCursor pages through the rest.
	DeploymentLogsHistoryMaxLimit = 1000
	// DeploymentLogsHistoryRetentionDays is how long durable logs are kept before
	// the object-store lifecycle rule deletes them.
	DeploymentLogsHistoryRetentionDays = 30
)

// Application error detection / reporting (the error.* resource)
const (
	// ErrorListDefaultLimit is the issue page size used when Limit is unset.
	ErrorListDefaultLimit = 50
	// ErrorListMaxLimit clamps the issue page size.
	ErrorListMaxLimit = 200

	// ErrorCreateMaxEvents bounds the number of reported errors per error.create
	// call (batch to amortise the round-trip).
	ErrorCreateMaxEvents = 100
	// ErrorReportMaxFrames bounds the stack frames carried by one reported error.
	ErrorReportMaxFrames = 100
	// ErrorReportMaxTypeLength bounds the reported exception type string.
	ErrorReportMaxTypeLength = 1024
	// ErrorSampleMaxBytes caps the stored sample stack-trace text (matches the
	// capture-side cap); a longer Sample is truncated server-side.
	ErrorSampleMaxBytes = 16 * 1024
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

	// waf.test sample request
	WAFTestMaxHeaders      = 32
	WAFTestMaxCookies      = 32
	WAFTestMaxValueLength  = 1024 // each header/cookie value, host
	WAFTestMaxPathLength   = 2048
	WAFTestMaxQueryLength  = 2048
	WAFTestMaxMethodLength = 16
	WAFTestMaxASN          = 4294967295 // ASNs are 32-bit
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

// Transform (parapet transformrule)
const (
	TransformMaxRules = 100

	// TransformMaxRuleIDLength matches parapet's 63-char cap on a rule id (rule
	// ids will label the future parapet_transform_matches series). NOTE the cap is
	// on the FULL stored id (<projectID>-<rand>), so the server must validate the
	// prefixed form, not just the client-facing short id.
	TransformMaxRuleIDLength = 63

	// TransformMaxFilterLength caps the CEL filter; it shares the WAF expression
	// surface so it uses the same budget.
	TransformMaxFilterLength = WAFMaxExpressionLength

	// TransformMaxOpsPerRule bounds the ordered op list per rule.
	TransformMaxOpsPerRule = 16

	// TransformMaxHeaderValueLength caps a set-header value (shares the WAF
	// expression budget).
	TransformMaxHeaderValueLength = 2048
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

// Notification (change-notification channels)
const (
	NotificationMaxURLLength           = 2048
	NotificationMaxSecretLength        = 1024
	NotificationMaxSubscriptionEntries = 64

	NotificationDefaultDeliveriesLimit = 50
	NotificationMaxDeliveriesLimit     = 100

	// Pull channels: per-channel inactivity TTL bounds (seconds; 0 = server
	// default) and the pull batch size.
	NotificationMinPullTTLSeconds = 60
	NotificationMaxPullTTLSeconds = 86400 // 24h
	NotificationDefaultPullLimit  = 100
	NotificationMaxPullLimit      = 1000
)
