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
