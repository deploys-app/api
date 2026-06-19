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
// Secret) and a Subscription filter (ResourceTypes, Actions, Outcomes). A change
// is delivered to a channel when it matches the subscription on every axis; an
// empty axis is a wildcard, so a channel with an empty subscription receives
// every change. Delivery is at-least-once: a receiver may see a change more than
// once and must dedup on it.
//
// Secret is WRITE-ONLY: it is accepted on Create/Update but never returned by
// Get/List (Config.Secret is always empty in responses). On Update, leave Secret
// empty to keep the stored secret; send a new value to replace it. Webhook
// deliveries are signed with HMAC-SHA256(Secret) in an "X-Deploys-Signature:
// sha256=<hex>" header so the receiver can authenticate them.
//
// Channel types: webhook (HTTPS POST of the JSON change payload) and discord
// (a Discord webhook URL).
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
}

// NotificationConfig is a channel's delivery configuration. Type is the channel
// kind ("webhook" or "discord"); URL is the delivery target; Secret is the
// write-only webhook signing key; InsecureSkipVerify disables TLS verification
// for HTTPS targets (self-signed certs) — the server still blocks private/
// link-local/metadata targets to avoid SSRF.
type NotificationConfig struct {
	Type               string `json:"type" yaml:"type"`                             // webhook|discord
	URL                string `json:"url" yaml:"url"`                               // delivery target
	Secret             string `json:"secret,omitempty" yaml:"secret,omitempty"`     // write-only signing key
	InsecureSkipVerify bool   `json:"insecureSkipVerify" yaml:"insecureSkipVerify"` // skip TLS verify
}

// NotificationSubscription filters which changes a channel receives. Each axis
// is matched independently and an empty axis is a wildcard, so the zero value
// subscribes to every change. Outcomes entries are "success" or "failure".
type NotificationSubscription struct {
	ResourceTypes []string `json:"resourceTypes" yaml:"resourceTypes"` // [] = all
	Actions       []string `json:"actions" yaml:"actions"`             // [] = all
	Outcomes      []string `json:"outcomes" yaml:"outcomes"`           // [] = all (success|failure)
}

func validNotificationName(v *validator.Validator, name string) {
	v.Must(ReValidName.MatchString(name), "name invalid "+ReValidNameStr)
	cnt := utf8.RuneCountInString(name)
	v.Mustf(cnt >= MinNameLength && cnt <= MaxNameLength, "name must have length between %d-%d characters", MinNameLength, MaxNameLength)
}

func validNotificationURL(v *validator.Validator, raw string) {
	v.Must(raw != "", "config.url required")
	v.Mustf(utf8.RuneCountInString(raw) <= NotificationMaxURLLength, "config.url must not exceed %d characters", NotificationMaxURLLength)
	if raw == "" {
		return
	}
	u, err := url.Parse(raw)
	if err != nil {
		v.Must(false, "config.url invalid")
		return
	}
	v.Must(u.Scheme == "http" || u.Scheme == "https", "config.url must be http or https")
	v.Must(u.Host != "", "config.url host required")
}

// validNotificationConfig validates the delivery config. requireSecret is true
// on Create (a webhook must carry its signing secret) and false on Update (an
// empty secret means "keep the stored one").
func validNotificationConfig(v *validator.Validator, cfg NotificationConfig, requireSecret bool) {
	ct := parseNotificationChannelType(cfg.Type)
	v.Must(ct.Valid(), "config.type must be webhook or discord")
	validNotificationURL(v, cfg.URL)
	if ct == NotificationChannelTypeWebhook && requireSecret {
		v.Must(cfg.Secret != "", "config.secret required for webhook")
	}
	v.Mustf(utf8.RuneCountInString(cfg.Secret) <= NotificationMaxSecretLength, "config.secret must not exceed %d characters", NotificationMaxSecretLength)
}

func validNotificationSubscription(v *validator.Validator, s NotificationSubscription) {
	total := len(s.ResourceTypes) + len(s.Actions) + len(s.Outcomes)
	v.Mustf(total <= NotificationMaxSubscriptionEntries, "subscription must not exceed %d entries", NotificationMaxSubscriptionEntries)
	for _, o := range s.Outcomes {
		v.Mustf(o == "success" || o == "failure", "subscription outcome %q invalid (want success or failure)", o)
	}
	for _, x := range s.ResourceTypes {
		v.Mustf(x != "" && utf8.RuneCountInString(x) <= 64, "subscription resourceType %q invalid", x)
	}
	for _, x := range s.Actions {
		v.Mustf(x != "" && utf8.RuneCountInString(x) <= 64, "subscription action %q invalid", x)
	}
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
	validNotificationConfig(v, m.Config, true)
	validNotificationSubscription(v, m.Subscription)

	return WrapValidate(v)
}

// NotificationUpdate replaces the whole channel configuration. Leave
// Config.Secret empty to keep the stored secret; set it to replace it.
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
	validNotificationConfig(v, m.Config, false)
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

// NotificationItem is the read view of a channel. Config.Secret is always empty.
type NotificationItem struct {
	Project      string                   `json:"project" yaml:"project"`
	Name         string                   `json:"name" yaml:"name"`
	Config       NotificationConfig       `json:"config" yaml:"config"` // Secret is ""
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
