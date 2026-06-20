package api

import (
	"strings"
	"testing"
)

func TestNotificationEvents(t *testing.T) {
	events := NotificationEvents()
	if len(events) == 0 {
		t.Fatal("the event catalog must not be empty")
	}
	// NotificationEvents returns a copy — mutating it must not affect the catalog.
	events[0] = "mutated"
	if NotificationEvents()[0] == "mutated" {
		t.Fatal("NotificationEvents must return a copy")
	}

	seen := map[string]bool{}
	for _, e := range NotificationEvents() {
		if seen[e] {
			t.Fatalf("duplicate event %q", e)
		}
		seen[e] = true
		// every catalog entry is a concrete resource.action: a valid pattern, with
		// exactly one dot and no wildcard segment (wildcards are grammar, not events).
		if !IsValidNotificationEvent(e) {
			t.Fatalf("catalog event %q is not a valid event pattern", e)
		}
		left, right, ok := strings.Cut(e, ".")
		if !ok || left == "" || right == "" || left == "*" || right == "*" {
			t.Fatalf("catalog event %q must be a concrete resource.action", e)
		}
	}
	// a known event a subscription would target.
	if !seen["deployment.deploy"] || !seen["role.grant"] {
		t.Fatal("catalog is missing expected events")
	}
}

func TestNotificationChannelType(t *testing.T) {
	cases := []struct {
		ct    NotificationChannelType
		s     string
		valid bool
	}{
		{NotificationChannelTypeWebhook, "webhook", true},
		{NotificationChannelTypeDiscord, "discord", true},
		{NotificationChannelTypePull, "pull", true},
	}
	for _, tc := range cases {
		if got := tc.ct.String(); got != tc.s {
			t.Fatalf("String(%d)=%q want %q", tc.ct, got, tc.s)
		}
		if got := parseNotificationChannelType(tc.s); got != tc.ct {
			t.Fatalf("parse(%q)=%d want %d", tc.s, got, tc.ct)
		}
		if got := tc.ct.Valid(); got != tc.valid {
			t.Fatalf("Valid(%q)=%v want %v", tc.s, got, tc.valid)
		}
	}
	if parseNotificationChannelType("nope") != NotificationChannelType(0) {
		t.Fatalf("unknown type must parse to 0")
	}
}

func validWebhookCreate() *NotificationCreate {
	return &NotificationCreate{
		Project: "p",
		Name:    "ops-hook",
		Config:  NotificationConfig{Type: "webhook", URL: "https://example.com/hook", Secret: "shh"},
	}
}

func TestNotificationCreateValid(t *testing.T) {
	if err := validWebhookCreate().Valid(); err != nil {
		t.Fatalf("a valid webhook create was rejected: %v", err)
	}
	// discord needs no secret (the webhook URL itself carries the token)
	disc := &NotificationCreate{
		Project: "p", Name: "ops-disc",
		Config: NotificationConfig{Type: "discord", URL: "https://discord.com/api/webhooks/1/abc"},
	}
	if err := disc.Valid(); err != nil {
		t.Fatalf("a valid discord create was rejected: %v", err)
	}
	// pull has no delivery target: no url, no secret. A bare pull (default TTL)
	// and one with an explicit in-range TTL must both validate.
	pull := &NotificationCreate{
		Project: "p", Name: "agent-1",
		Config: NotificationConfig{Type: "pull"},
	}
	if err := pull.Valid(); err != nil {
		t.Fatalf("a valid pull create was rejected: %v", err)
	}
	pullTTL := &NotificationCreate{
		Project: "p", Name: "agent-2",
		Config: NotificationConfig{Type: "pull", PullTTLSeconds: 600},
	}
	if err := pullTTL.Valid(); err != nil {
		t.Fatalf("a valid pull create with TTL was rejected: %v", err)
	}
	// every event-pattern form must validate.
	withEvents := validWebhookCreate()
	withEvents.Subscription.Events = []string{"*", "deployment.*", "*.delete", "deployment.deploy", "pull-secret.create"}
	if err := withEvents.Valid(); err != nil {
		t.Fatalf("valid event patterns were rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*NotificationCreate)
		want   string
	}{
		{"missing project", func(m *NotificationCreate) { m.Project = "" }, "project required"},
		{"bad name", func(m *NotificationCreate) { m.Name = "Bad Name" }, "name invalid"},
		{"unknown type", func(m *NotificationCreate) { m.Config.Type = "telegram" }, "config.type"},
		{"unsupported slack type", func(m *NotificationCreate) { m.Config.Type = "slack" }, "config.type"},
		{"missing url", func(m *NotificationCreate) { m.Config.URL = "" }, "config.url required"},
		{"non-http url", func(m *NotificationCreate) { m.Config.URL = "ftp://x" }, "http or https"},
		{"webhook missing secret", func(m *NotificationCreate) { m.Config.Secret = "" }, "secret required"},
		{"bad outcome", func(m *NotificationCreate) { m.Subscription.Outcomes = []string{"maybe"} }, "outcome"},
		{"event no dot", func(m *NotificationCreate) { m.Subscription.Events = []string{"deployment"} }, "event"},
		{"event empty side", func(m *NotificationCreate) { m.Subscription.Events = []string{"deployment."} }, "event"},
		{"event bad char", func(m *NotificationCreate) { m.Subscription.Events = []string{"deployment.de ploy"} }, "event"},
		{"webhook with pull ttl", func(m *NotificationCreate) { m.Config.PullTTLSeconds = 600 }, "only valid for pull"},
		{"pull with url", func(m *NotificationCreate) { m.Config = NotificationConfig{Type: "pull", URL: "https://x/y"} }, "url must be empty"},
		{"pull with secret", func(m *NotificationCreate) { m.Config = NotificationConfig{Type: "pull", Secret: "shh"} }, "secret must be empty"},
		{"pull ttl too small", func(m *NotificationCreate) { m.Config = NotificationConfig{Type: "pull", PullTTLSeconds: 30} }, "pullTtlSeconds"},
		{"pull ttl too large", func(m *NotificationCreate) { m.Config = NotificationConfig{Type: "pull", PullTTLSeconds: 999999} }, "pullTtlSeconds"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validWebhookCreate()
			tc.mutate(m)
			err := m.Valid()
			if err == nil {
				t.Fatalf("expected a validation error for %s, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error to contain %q, got: %v", tc.want, err)
			}
		})
	}
}

func TestNotificationUpdateAllowsEmptySecret(t *testing.T) {
	// On update an empty secret means "keep the stored one", so a webhook update
	// without a secret must validate.
	m := &NotificationUpdate{
		Project: "p", Name: "ops-hook",
		Config: NotificationConfig{Type: "webhook", URL: "https://example.com/hook"},
	}
	if err := m.Valid(); err != nil {
		t.Fatalf("webhook update with empty secret must be valid, got: %v", err)
	}
}

func TestNotificationUpdateAllowsEmptyURL(t *testing.T) {
	// The URL is write-only on update (an empty value keeps the stored target, so
	// a redacted Discord webhook token need not be retyped to edit other fields).
	discord := &NotificationUpdate{
		Project: "p", Name: "ops-disc",
		Config: NotificationConfig{Type: "discord"},
	}
	if err := discord.Valid(); err != nil {
		t.Fatalf("discord update with empty url must be valid, got: %v", err)
	}
	webhook := &NotificationUpdate{
		Project: "p", Name: "ops-hook",
		Config: NotificationConfig{Type: "webhook"},
	}
	if err := webhook.Valid(); err != nil {
		t.Fatalf("webhook update with empty url must be valid, got: %v", err)
	}
	// a non-empty URL is still format-checked on update
	bad := &NotificationUpdate{
		Project: "p", Name: "ops-disc",
		Config: NotificationConfig{Type: "discord", URL: "ftp://nope"},
	}
	if err := bad.Valid(); err == nil || !strings.Contains(err.Error(), "http or https") {
		t.Fatalf("update with a malformed url must still fail, got: %v", err)
	}
	// Create still requires the URL.
	create := &NotificationCreate{
		Project: "p", Name: "ops-disc",
		Config: NotificationConfig{Type: "discord"},
	}
	if err := create.Valid(); err == nil || !strings.Contains(err.Error(), "config.url required") {
		t.Fatalf("create without a url must fail, got: %v", err)
	}
}

func TestNotificationNotPublicBindable(t *testing.T) {
	// channel reads expose URLs (internal Discord hooks), so the .get/.list
	// carve-out must keep every notification permission off public bindings.
	for _, p := range []string{
		"notification.get", "notification.list", "notification.create",
		"notification.update", "notification.delete", "notification.test",
		"notification.pull", "notification.*",
	} {
		if IsPublicBindablePermission(p) {
			t.Fatalf("%s must not be public-bindable", p)
		}
	}
	// sanity: an ordinary read permission is still public-bindable.
	if !IsPublicBindablePermission("scheduler.get") {
		t.Fatalf("scheduler.get should remain public-bindable")
	}
}
