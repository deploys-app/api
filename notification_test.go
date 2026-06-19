package api

import (
	"strings"
	"testing"
)

func TestNotificationChannelType(t *testing.T) {
	cases := []struct {
		ct    NotificationChannelType
		s     string
		valid bool
	}{
		{NotificationChannelTypeWebhook, "webhook", true},
		{NotificationChannelTypeDiscord, "discord", true},
		{NotificationChannelTypeSlack, "slack", false}, // reserved, not deliverable
		{NotificationChannelTypeEmail, "email", false}, // reserved, not deliverable
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

	cases := []struct {
		name   string
		mutate func(*NotificationCreate)
		want   string
	}{
		{"missing project", func(m *NotificationCreate) { m.Project = "" }, "project required"},
		{"bad name", func(m *NotificationCreate) { m.Name = "Bad Name" }, "name invalid"},
		{"unknown type", func(m *NotificationCreate) { m.Config.Type = "telegram" }, "config.type"},
		{"reserved slack type", func(m *NotificationCreate) { m.Config.Type = "slack" }, "config.type"},
		{"missing url", func(m *NotificationCreate) { m.Config.URL = "" }, "config.url required"},
		{"non-http url", func(m *NotificationCreate) { m.Config.URL = "ftp://x" }, "http or https"},
		{"webhook missing secret", func(m *NotificationCreate) { m.Config.Secret = "" }, "secret required"},
		{"bad outcome", func(m *NotificationCreate) { m.Subscription.Outcomes = []string{"maybe"} }, "outcome"},
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

func TestNotificationNotPublicBindable(t *testing.T) {
	// channel reads expose URLs (internal Discord hooks), so the .get/.list
	// carve-out must keep every notification permission off public bindings.
	for _, p := range []string{
		"notification.get", "notification.list", "notification.create",
		"notification.update", "notification.delete", "notification.test", "notification.*",
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
