package api

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/acoshift/arpc/v2"
)

var (
	ErrUnauthorized                  = newError("api: unauthorized")
	ErrForbidden                     = newError("api: forbidden")
	ErrLocationNotAvailable          = newError("api: location not available")
	ErrLocationNotSupport            = newError("api: location not support")
	ErrSIDNotAvailable               = newError("api: sid not available")
	ErrRoleNotFound                  = newError("api: role not found")
	ErrRoleSIDNotAvailable           = newError("api: role sid not available")
	ErrRolePublicBindingForbidden    = newError("api: allUsers and allAuthenticatedUsers can only be granted roles with read-only, non-sensitive permissions")
	ErrProjectNotFound               = newError("api: project not found")
	ErrBillingAccountNotFound        = newError("api: billing account not found")
	ErrBillingAccountNotActive       = newError("api: billing account not active, please contact us via email to activate billing account")
	ErrBillingAccountInUsed          = newError("api: billing account in used")
	ErrDeploymentNotFound            = newError("api: deployment not found")
	ErrInvalidRouteTarget            = newError("api: invalid route target")
	ErrCanNotDelete                  = newError("api: can not delete")
	ErrCanNotPause                   = newError("api: can not pause")
	ErrCanNotResume                  = newError("api: can not resume")
	ErrCanNotRestart                 = newError("api: can not restart")
	ErrWorkloadIdentityNotFound      = newError("api: workload identity not found")
	ErrWorkloadIdentityAlreadyExists = newError("api: workload identity already exists")
	ErrWorkloadIdentityInUse         = newError("api: workload identity in use")
	ErrUserNotFound                  = newError("api: user not found")
	ErrDomainNotAvailable            = newError("api: domain not available")
	ErrReplicasInvalid               = newError("api: replicas invalid")
	ErrCanMapOnlyWebService          = newError("api: can not map to deployment other than web service type")
	ErrScheduleInvalid               = newError("api: schedule invalid")
	ErrTypeInvalid                   = newError("api: type invalid")
	ErrTypeNotAllowChange            = newError("api: type not allow to change")
	ErrDiskNotFound                  = newError("api: disk not found")
	ErrDiskSizeMustScaleUp           = newError("api: disk size must scale up")
	ErrDiskAlreadyExists             = newError("api: disk already exists")
	ErrDiskInUsed                    = newError("api: disk in use")
	ErrPullSecretNameNotAvailable    = newError("api: pull secret name not available")
	ErrPullSecretNotFound            = newError("api: pull secret not found")
	ErrPullSecretInUse               = newError("api: pull secret in use")
	ErrServiceAccountNotFound        = newError("api: service account not found")
	ErrServiceAccountAlreadyExists   = newError("api: service account already exists")
	ErrMaximumDeploymentReach        = newError("api: maximum deployment reach")
	ErrRouteNotFound                 = newError("api: route not found")
	ErrDomainInUsed                  = newError("api: domain in used")
	ErrPurgeFailed                   = newError("api: purge failed")
	ErrDomainNotFound                = newError("api: domain not found")
	ErrDomainNotVerified             = newError("api: domain dns not verified, please configure dns and wait for verification")
	ErrDomainCanNotPurge             = newError("api: domain can not purge")
	ErrDomainPurgeInvalid            = newError("api: domain purge invalid")
	ErrEmailDomainNotFound           = newError("api: email domain not found")
	ErrTTLDeploymentNotAllowRoute    = newError("api: ttl deployment not allow to be set by route")
	ErrEnvGroupNotFound              = newError("api: env group not found")
	ErrEnvGroupAlreadyExists         = newError("api: env group already exists")
	ErrEnvGroupInUse                 = newError("api: env group in use")
	ErrInvoiceNotFound               = newError("api: invoice not found")
	ErrInvoicePDFUnavailable         = newError("api: invoice pdf export is not available")
	ErrInvoicePDFFailed              = newError("api: could not generate the invoice pdf, please try again")
	ErrInvoiceNotPaid                = newError("api: invoice is not paid")
	ErrWAFZoneNotFound               = newError("api: waf zone not found")
	ErrWAFRuleInvalid                = newError("api: waf rule invalid")
	ErrCacheZoneNotFound             = newError("api: cache zone not found")
	ErrCacheOverrideInvalid          = newError("api: cache override invalid")
	ErrGitHubRepoAlreadyLinked       = newError("api: github repository already linked")
	ErrGitHubRepoLinkNotFound        = newError("api: github repository link not found")
	ErrGitHubTokenInvalid            = newError("api: github token invalid")
	ErrGitHubSHAMismatch             = newError("api: github sha does not match token")
	ErrGitHubProjectMismatch         = newError("api: github project does not match repository link")
	ErrGitHubAppNotInstalled         = newError("api: github app is not installed on the repository")
	ErrGitHubBranchNotAllowed        = newError("api: github ref is not the configured production branch")
	ErrGitHubProductionDisabled      = newError("api: github production deploys are disabled for this repository")
	ErrGitHubPreviewsDisabled        = newError("api: github pull request previews are disabled for this repository")
)

var AllErrors []error

func newError(msg string) error {
	err := arpc.NewError(msg)
	AllErrors = append(AllErrors, err)
	return err
}

// DomainInUsedRouteLimit caps how many route identifiers DomainInUsedError
// spells out before collapsing the remainder into "(+N more)", so a wildcard
// domain with many routes can't produce an unbounded message.
const DomainInUsedRouteLimit = 10

// DomainInUsedError is returned when a domain cannot be deleted because routes
// still depend on it. It carries the blocking routes so server code can act on
// them programmatically (errors.As), and renders them into the message string
// the console parses.
//
// It implements arpc's OKError (so arpc answers 200 / ok:false instead of
// masking it as a 500 "internal error") and marshals to the same
// {code, message} envelope as the package's other errors, so returning it from
// a handler keeps the wire contract identical to the sentinels.
type DomainInUsedError struct {
	// Routes are the "<host><path>" identifiers of the routes still pinning the
	// domain (e.g. "app.example.com/api").
	Routes []string
}

var (
	_ error          = (*DomainInUsedError)(nil)
	_ json.Marshaler = (*DomainInUsedError)(nil)
	_ arpc.OKError   = (*DomainInUsedError)(nil)
)

// Error renders the sorted, capped message — the wire contract consumed by the
// console — e.g.:
//
//	api: domain in used by route(s): a.example.com/, b.example.com/api (+3 more)
//
// With no routes it degrades to the bare ErrDomainInUsed message.
func (e *DomainInUsedError) Error() string {
	if len(e.Routes) == 0 {
		return "api: domain in used"
	}

	rs := append([]string(nil), e.Routes...)
	sort.Strings(rs)

	shown := rs
	if len(shown) > DomainInUsedRouteLimit {
		shown = shown[:DomainInUsedRouteLimit]
	}
	msg := "api: domain in used by route(s): " + strings.Join(shown, ", ")
	if len(rs) > DomainInUsedRouteLimit {
		msg += fmt.Sprintf(" (+%d more)", len(rs)-DomainInUsedRouteLimit)
	}
	return msg
}

// OKError marks the error as a 200 / ok:false response, matching arpc.Error so
// arpc doesn't mask it as a 500 "internal error".
func (e *DomainInUsedError) OKError() {}

// MarshalJSON emits the same {code, message} envelope as arpc.Error so the
// console keeps reading error.message unchanged.
func (e *DomainInUsedError) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Code    string `json:"code,omitempty"`
		Message string `json:"message,omitempty"`
	}{Message: e.Error()})
}
