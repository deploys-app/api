package api

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/moonrhythm/validator"
)

// Notification manages a project's notification channels: delivery endpoints
// (webhooks, Discord) that receive a change event whenever a project resource is
// written. Channels are project-scoped and location-less — a channel is
// addressed by (project, name) like an env group or a scheduler job.
//
// Each channel carries a delivery Config (Type, URL, and a write-only signing
// Secret) and a Subscription filter (Events, Outcomes). A change is delivered to
// a channel when it matches the subscription on every axis; an empty axis is a
// wildcard, so a channel with an empty subscription receives every change.
// Delivery is at-least-once: a receiver may see a change more than once and must
// dedup on it.
//
// Secret is WRITE-ONLY: it is accepted on Create/Update but never returned by
// Get/List (Config.Secret is always empty in responses). On Update, leave Secret
// empty to keep the stored secret; send a new value to replace it. Webhook
// deliveries are signed with HMAC-SHA256(Secret) in an "X-Deploys-Signature:
// sha256=<hex>" header so the receiver can authenticate them.
//
// A Discord webhook URL embeds a secret token (.../webhooks/{id}/{token}), so
// the URL is treated like the Secret: Get/List return it with the token redacted,
// and on Update an empty URL keeps the stored target (retype the full URL only to
// change it).
//
// Channel types: webhook (HTTPS POST of the JSON change payload), discord (a
// Discord webhook URL), and pull (no delivery target — a consumer fetches changes
// with Pull on its own schedule; useful for a local agent that has no public URL).
type Notification interface {
	// Create requires the `notification.create` permission.
	Create(ctx context.Context, m *NotificationCreate) (*Empty, error)
	// Update requires the `notification.update` permission.
	Update(ctx context.Context, m *NotificationUpdate) (*Empty, error)
	// Get requires the `notification.get` permission.
	Get(ctx context.Context, m *NotificationGet) (*NotificationItem, error)
	// List requires the `notification.list` permission.
	List(ctx context.Context, m *NotificationList) (*NotificationListResult, error)
	// Delete requires the `notification.delete` permission.
	Delete(ctx context.Context, m *NotificationDelete) (*Empty, error)
	// Test delivers a synthetic change to the channel synchronously and returns a
	// classified result (status/latency/error only — never the response body).
	// Requires the `notification.test` permission.
	Test(ctx context.Context, m *NotificationTest) (*NotificationDelivery, error)
	// Deliveries lists a channel's recent delivery attempts, newest first.
	// Requires the `notification.get` permission.
	Deliveries(ctx context.Context, m *NotificationDeliveries) (*NotificationDeliveriesResult, error)
	// Pull fetches the next batch of change events for a pull channel and advances
	// the channel's server-stored cursor (see NotificationPull). Delivery is
	// at-least-once. Requires the `notification.pull` permission.
	Pull(ctx context.Context, m *NotificationPull) (*NotificationPullResult, error)
}

// NotificationConfig is a channel's delivery configuration. Type is the channel
// kind ("webhook", "discord", or "pull"); URL is the delivery target; Secret is
// the write-only webhook signing key; InsecureSkipVerify disables TLS
// verification for HTTPS targets (self-signed certs) — the server still blocks
// private/link-local/metadata targets to avoid SSRF.
//
// A "pull" channel has no delivery target: URL and Secret must be empty, and
// PullTTLSeconds sets how long the channel survives without a Pull before it is
// auto-deleted (0 = server default). PullTTLSeconds is ignored for push channels.
type NotificationConfig struct {
	Type               string `json:"type" yaml:"type"`                                         // webhook|discord|pull
	URL                string `json:"url" yaml:"url"`                                           // delivery target (empty for pull; on Update empty keeps stored; Discord token redacted in responses)
	Secret             string `json:"secret,omitempty" yaml:"secret,omitempty"`                 // write-only signing key
	InsecureSkipVerify bool   `json:"insecureSkipVerify" yaml:"insecureSkipVerify"`             // skip TLS verify
	PullTTLSeconds     int    `json:"pullTtlSeconds,omitempty" yaml:"pullTtlSeconds,omitempty"` // pull only; 0 = server default
}

// NotificationSubscription filters which changes a channel receives. A change is
// delivered when it matches Events AND Outcomes; an empty axis is a wildcard, so
// the zero value subscribes to every change.
//
// Events are "<resourceType>.<action>" patterns using the same grammar as IAM
// permissions, extended with a leading "*." form. Examples:
// "*" = every change; "deployment.*" = any action on deployments; "*.delete" =
// a delete of any resource; "deployment.deploy" = exactly that resource+action.
//
// This replaces the former independent ResourceTypes/Actions axes, which could
// only express their cross-product (never a specific resource+action pair).
// Outcomes entries are "success" or "failure".
type NotificationSubscription struct {
	Events   []string `json:"events" yaml:"events"`     // [] = all; "<resource>.<action>" patterns (*, r.*, *.a, r.a)
	Outcomes []string `json:"outcomes" yaml:"outcomes"` // [] = all (success|failure)
}

func validNotificationName(v *validator.Validator, name string) {
	v.Must(ReValidName.MatchString(name), "name invalid: "+ReValidNameDesc)
	cnt := utf8.RuneCountInString(name)
	v.Mustf(cnt >= MinNameLength && cnt <= MaxNameLength, "name must have length between %d-%d characters", MinNameLength, MaxNameLength)
}

func validNotificationURL(v *validator.Validator, raw string, required bool) {
	if raw == "" {
		// On Update the URL is write-optional: an empty value keeps the stored
		// target (mirrors the Secret), so it is only required on Create.
		v.Must(!required, "config.url required")
		return
	}
	v.Mustf(utf8.RuneCountInString(raw) <= NotificationMaxURLLength, "config.url must not exceed %d characters", NotificationMaxURLLength)
	u, err := url.Parse(raw)
	if err != nil {
		v.Must(false, "config.url invalid")
		return
	}
	v.Must(u.Scheme == "http" || u.Scheme == "https", "config.url must be http or https")
	v.Must(u.Host != "", "config.url host required")
}

// validNotificationConfig validates the delivery config. requireSecret and
// requireURL are true on Create and false on Update: on Update an empty signing
// secret keeps the stored one, and an empty URL keeps the stored delivery target
// (so the redacted Discord webhook token never has to be retyped to edit other
// fields). Both are write-only — accepted but never returned verbatim.
func validNotificationConfig(v *validator.Validator, cfg NotificationConfig, requireSecret, requireURL bool) {
	ct := parseNotificationChannelType(cfg.Type)
	v.Must(ct.Valid(), "config.type must be webhook, discord, or pull")

	if ct == NotificationChannelTypePull {
		// A pull channel is consumed via notification.pull; it has no delivery
		// target or signing secret.
		v.Must(cfg.URL == "", "config.url must be empty for pull")
		v.Must(cfg.Secret == "", "config.secret must be empty for pull")
		validNotificationPullTTL(v, cfg.PullTTLSeconds)
		return
	}

	// Push channels (webhook/discord, and any unknown type which already failed
	// the Valid() check above) deliver to a URL.
	validNotificationURL(v, cfg.URL, requireURL)
	if ct == NotificationChannelTypeWebhook && requireSecret {
		v.Must(cfg.Secret != "", "config.secret required for webhook")
	}
	v.Mustf(utf8.RuneCountInString(cfg.Secret) <= NotificationMaxSecretLength, "config.secret must not exceed %d characters", NotificationMaxSecretLength)
	v.Must(cfg.PullTTLSeconds == 0, "config.pullTtlSeconds is only valid for pull channels")
}

// validNotificationPullTTL checks a pull channel's per-channel inactivity TTL.
// 0 means "use the server default"; any other value must fall within the bounds.
func validNotificationPullTTL(v *validator.Validator, secs int) {
	if secs == 0 {
		return
	}
	v.Mustf(secs >= NotificationMinPullTTLSeconds && secs <= NotificationMaxPullTTLSeconds,
		"config.pullTtlSeconds must be 0 (default) or between %d and %d", NotificationMinPullTTLSeconds, NotificationMaxPullTTLSeconds)
}

func validNotificationSubscription(v *validator.Validator, s NotificationSubscription) {
	total := len(s.Events) + len(s.Outcomes)
	v.Mustf(total <= NotificationMaxSubscriptionEntries, "subscription must not exceed %d entries", NotificationMaxSubscriptionEntries)
	for _, o := range s.Outcomes {
		v.Mustf(o == "success" || o == "failure", "subscription outcome %q invalid (want success or failure)", o)
	}
	for _, e := range s.Events {
		v.Mustf(utf8.RuneCountInString(e) <= 64 && IsValidNotificationEvent(e),
			"subscription event %q invalid (want *, resource.*, *.action, or resource.action)", e)
	}
}

// IsValidNotificationEvent reports whether e is a well-formed event pattern: the
// bare wildcard "*", or "<left>.<right>" where each side is "*" or a token of
// letters/digits/-/_ (resource types use hyphens, actions are camelCase). It is
// exported so servers can reuse the exact grammar the client validates against.
func IsValidNotificationEvent(e string) bool {
	if e == "*" {
		return true
	}
	left, right, ok := strings.Cut(e, ".")
	return ok && validNotificationEventSegment(left) && validNotificationEventSegment(right)
}

func validNotificationEventSegment(s string) bool {
	if s == "*" {
		return true
	}
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// notificationEvents is the catalog of concrete "<resource>.<action>" events the
// platform emits — every write that produces an audit-log entry, and therefore
// every event a subscription can match. It mirrors Permissions(): a discovery
// list a client can present when building a subscription, grouped by resource.
//
// Subscriptions are not limited to this list — a pattern may use the wildcard
// forms IsValidNotificationEvent accepts ("*", "<resource>.*", "*.<action>"), and
// the list is advisory (not enforced by validation) so a newly added event keeps
// working before this catalog catches up. The resource segments mirror the audit
// resourceType exactly (camelCase: pullSecret, serviceAccount, envGroup; note the
// historical lowercase workloadidentity); keep in sync with the apiserver
// recordChange/recordAudit call sites.
var notificationEvents = []string{
	"cache.set", "cache.delete",
	"database.create",
	"deployment.deploy", "deployment.rollback", "deployment.restart",
	"deployment.pause", "deployment.resume", "deployment.delete",
	"disk.create", "disk.update", "disk.delete",
	"domain.create", "domain.purgeCache", "domain.delete",
	"envGroup.create", "envGroup.update", "envGroup.delete",
	"githubInstallation.create",
	"githubRepo.link", "githubRepo.update", "githubRepo.unlink",
	"notification.create", "notification.update", "notification.delete",
	"project.create", "project.update", "project.delete",
	"pullSecret.create", "pullSecret.delete",
	"role.create", "role.update", "role.delete", "role.grant", "role.revoke",
	"route.create", "route.delete",
	"scheduler.create", "scheduler.update", "scheduler.delete",
	"scheduler.pause", "scheduler.resume", "scheduler.trigger",
	"serviceAccount.create", "serviceAccount.update", "serviceAccount.delete",
	"serviceAccount.createKey", "serviceAccount.deleteKey",
	"site.publish",
	"waf.set", "waf.delete",
	"workloadidentity.create", "workloadidentity.delete",
}

// NotificationEvents returns the catalog of concrete change events a notification
// subscription can match — the discovery list for a subscription UI (see
// notificationEvents). The returned slice is a copy. Wildcard patterns ("*",
// "<resource>.*", "*.<action>") are also valid in a subscription but are not
// listed here; they are formed per IsValidNotificationEvent.
func NotificationEvents() []string {
	xs := make([]string, len(notificationEvents))
	copy(xs, notificationEvents)
	return xs
}

type NotificationCreate struct {
	Project      string                   `json:"project" yaml:"project"`
	Name         string                   `json:"name" yaml:"name"`
	Config       NotificationConfig       `json:"config" yaml:"config"`
	Subscription NotificationSubscription `json:"subscription" yaml:"subscription"`
	Disabled     bool                     `json:"disabled" yaml:"disabled"`
}

func (m *NotificationCreate) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	m.Config.Type = strings.TrimSpace(m.Config.Type)
	m.Config.URL = strings.TrimSpace(m.Config.URL)

	v := validator.New()
	v.Must(m.Project != "", "project required")
	validNotificationName(v, m.Name)
	validNotificationConfig(v, m.Config, true, true)
	validNotificationSubscription(v, m.Subscription)

	return WrapValidate(v)
}

// NotificationUpdate replaces the whole channel configuration. Leave
// Config.Secret empty to keep the stored secret; set it to replace it. Likewise
// leave Config.URL empty to keep the stored delivery target (set it to replace) —
// this lets a Discord channel, whose URL is returned redacted, be edited without
// retyping the webhook token.
type NotificationUpdate struct {
	Project      string                   `json:"project" yaml:"project"`
	Name         string                   `json:"name" yaml:"name"`
	Config       NotificationConfig       `json:"config" yaml:"config"`
	Subscription NotificationSubscription `json:"subscription" yaml:"subscription"`
	Disabled     bool                     `json:"disabled" yaml:"disabled"`
}

func (m *NotificationUpdate) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	m.Config.Type = strings.TrimSpace(m.Config.Type)
	m.Config.URL = strings.TrimSpace(m.Config.URL)

	v := validator.New()
	v.Must(m.Project != "", "project required")
	validNotificationName(v, m.Name)
	validNotificationConfig(v, m.Config, false, false)
	validNotificationSubscription(v, m.Subscription)

	return WrapValidate(v)
}

type NotificationGet struct {
	Project string `json:"project" yaml:"project"`
	Name    string `json:"name" yaml:"name"`
}

func (m *NotificationGet) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	v := validator.New()
	v.Must(m.Project != "", "project required")
	validNotificationName(v, m.Name)
	return WrapValidate(v)
}

type NotificationDelete struct {
	Project string `json:"project" yaml:"project"`
	Name    string `json:"name" yaml:"name"`
}

func (m *NotificationDelete) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	v := validator.New()
	v.Must(m.Project != "", "project required")
	validNotificationName(v, m.Name)
	return WrapValidate(v)
}

type NotificationTest struct {
	Project string `json:"project" yaml:"project"`
	Name    string `json:"name" yaml:"name"`
}

func (m *NotificationTest) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	v := validator.New()
	v.Must(m.Project != "", "project required")
	validNotificationName(v, m.Name)
	return WrapValidate(v)
}

type NotificationList struct {
	Project string `json:"project" yaml:"project"`
}

func (m *NotificationList) Valid() error {
	v := validator.New()
	v.Must(m.Project != "", "project required")
	return WrapValidate(v)
}

type NotificationDeliveries struct {
	Project string    `json:"project" yaml:"project"`
	Name    string    `json:"name" yaml:"name"`
	After   time.Time `json:"after" yaml:"after"`
	Before  time.Time `json:"before" yaml:"before"`
	Limit   int       `json:"limit" yaml:"limit"`
}

func (m *NotificationDeliveries) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	v := validator.New()
	v.Must(m.Project != "", "project required")
	validNotificationName(v, m.Name)
	if err := WrapValidate(v); err != nil {
		return err
	}
	if m.Limit <= 0 {
		m.Limit = NotificationDefaultDeliveriesLimit
	}
	if m.Limit > NotificationMaxDeliveriesLimit {
		m.Limit = NotificationMaxDeliveriesLimit
	}
	return nil
}

// NotificationPull fetches the next batch of change events for a pull channel and
// advances the channel's server-stored cursor. Pass the Cursor returned by the
// previous call as Ack once that batch has been durably handled — the server only
// advances past acked events, so an unacked batch is redelivered (delivery is
// at-least-once; making progress requires acking). Each Pull also stamps the
// channel's liveness, deferring its inactivity auto-delete.
type NotificationPull struct {
	Project string `json:"project" yaml:"project"`
	Name    string `json:"name" yaml:"name"`
	Ack     int64  `json:"ack" yaml:"ack"`     // Cursor from the previous pull, once handled; 0 = don't advance
	Limit   int    `json:"limit" yaml:"limit"` // max events; clamped to [1, NotificationMaxPullLimit]
}

func (m *NotificationPull) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	v := validator.New()
	v.Must(m.Project != "", "project required")
	validNotificationName(v, m.Name)
	v.Must(m.Ack >= 0, "ack must not be negative")
	if err := WrapValidate(v); err != nil {
		return err
	}
	if m.Limit <= 0 {
		m.Limit = NotificationDefaultPullLimit
	}
	if m.Limit > NotificationMaxPullLimit {
		m.Limit = NotificationMaxPullLimit
	}
	return nil
}

// NotificationPullResult is a batch of change events for a pull channel. Events
// are already subscription-filtered and ordered oldest-first. Cursor is the
// outbox position scanned by this call — pass it back as NotificationPull.Ack on
// the next call once the events are handled. HasMore is true when the batch hit
// Limit and more events are immediately available, so the consumer should pull
// again before idling.
type NotificationPullResult struct {
	Project string               `json:"project" yaml:"project"`
	Name    string               `json:"name" yaml:"name"`
	Events  []ChangeEventPayload `json:"events" yaml:"events"`
	Cursor  int64                `json:"cursor" yaml:"cursor"`
	HasMore bool                 `json:"hasMore" yaml:"hasMore"`
}

func (m *NotificationPullResult) Table() [][]string {
	table := [][]string{
		{"TIME", "ACTOR", "ACTION", "RESOURCE", "OUTCOME"},
	}
	for _, e := range m.Events {
		res := e.ResourceType
		if e.ResourceName != "" {
			res += "/" + e.ResourceName
		}
		table = append(table, []string{
			age(e.Time), e.Actor, e.Action, res, e.Outcome,
		})
	}
	return table
}

// NotificationItem is the read view of a channel. Config.Secret is always empty,
// and a Discord Config.URL is returned with its webhook token redacted.
type NotificationItem struct {
	Project      string                   `json:"project" yaml:"project"`
	Name         string                   `json:"name" yaml:"name"`
	Config       NotificationConfig       `json:"config" yaml:"config"` // Secret is ""; Discord URL token redacted
	Subscription NotificationSubscription `json:"subscription" yaml:"subscription"`
	Disabled     bool                     `json:"disabled" yaml:"disabled"`
	CreatedAt    time.Time                `json:"createdAt" yaml:"createdAt"`
	CreatedBy    string                   `json:"createdBy" yaml:"createdBy"`
	UpdatedAt    time.Time                `json:"updatedAt" yaml:"updatedAt"`
	UpdatedBy    string                   `json:"updatedBy" yaml:"updatedBy"`
}

func notificationStatus(disabled bool) string {
	if disabled {
		return "disabled"
	}
	return "enabled"
}

func (m *NotificationItem) Table() [][]string {
	return [][]string{
		{"NAME", "TYPE", "STATUS", "AGE"},
		{m.Name, m.Config.Type, notificationStatus(m.Disabled), age(m.CreatedAt)},
	}
}

type NotificationListResult struct {
	Project string              `json:"project" yaml:"project"`
	Items   []*NotificationItem `json:"items" yaml:"items"`
}

func (m *NotificationListResult) Table() [][]string {
	table := [][]string{
		{"NAME", "TYPE", "STATUS", "AGE"},
	}
	for _, x := range m.Items {
		table = append(table, []string{
			x.Name,
			x.Config.Type,
			notificationStatus(x.Disabled),
			age(x.CreatedAt),
		})
	}
	return table
}

// Delivery result states, mirroring the scheduler invocation states.
const (
	NotificationResultPending = "pending"
	NotificationResultSuccess = "success"
	NotificationResultRetry   = "retry"
	NotificationResultFailed  = "failed"
)

// NotificationDelivery is one recorded delivery attempt (and the Test result).
// HTTPStatus is 0 when no response was received (connection refused, DNS
// failure, timeout, blocked target); Error holds the classified reason and
// never includes the response body or headers.
type NotificationDelivery struct {
	ID         string    `json:"id" yaml:"id"`
	StartedAt  time.Time `json:"startedAt" yaml:"startedAt"`
	Result     string    `json:"result" yaml:"result"` // pending|success|retry|failed
	HTTPStatus int       `json:"httpStatus" yaml:"httpStatus"`
	LatencyMs  int       `json:"latencyMs" yaml:"latencyMs"`
	Error      string    `json:"error" yaml:"error"`
}

func notificationDeliveryRow(x *NotificationDelivery) []string {
	status := ""
	if x.HTTPStatus > 0 {
		status = strconv.Itoa(x.HTTPStatus)
	}
	return []string{
		age(x.StartedAt),
		x.Result,
		status,
		strconv.Itoa(x.LatencyMs) + "ms",
		x.Error,
	}
}

func (m *NotificationDelivery) Table() [][]string {
	return [][]string{
		{"TIME", "RESULT", "STATUS", "LATENCY", "ERROR"},
		notificationDeliveryRow(m),
	}
}

type NotificationDeliveriesResult struct {
	Project string                  `json:"project" yaml:"project"`
	Name    string                  `json:"name" yaml:"name"`
	Items   []*NotificationDelivery `json:"items" yaml:"items"`
}

func (m *NotificationDeliveriesResult) Table() [][]string {
	table := [][]string{
		{"TIME", "RESULT", "STATUS", "LATENCY", "ERROR"},
	}
	for _, x := range m.Items {
		table = append(table, notificationDeliveryRow(x))
	}
	return table
}

// ChangeEventPayload is the JSON body delivered to webhook channels (the
// reference schema for receivers). It carries only the change's audit-safe
// fields — never a secret. Project is the project sid; ResourceID is the
// resource's numeric id as a string ("" when the change had no id); Time is when
// the change occurred.
type ChangeEventPayload struct {
	Project      string    `json:"project"`
	Location     string    `json:"location,omitempty"`
	Actor        string    `json:"actor"`
	ActorType    string    `json:"actorType"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resourceType"`
	ResourceID   string    `json:"resourceId,omitempty"`
	ResourceName string    `json:"resourceName,omitempty"`
	Outcome      string    `json:"outcome"`
	Message      string    `json:"message,omitempty"`
	Time         time.Time `json:"time"`
}
