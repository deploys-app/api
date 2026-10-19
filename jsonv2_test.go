package api

import (
	json "encoding/json/v2"
	"strings"
	"testing"
	"time"
)

func TestLocationFeaturesJSON(t *testing.T) {
	enabled := &struct{}{}
	got, err := json.Marshal(LocationFeatures{
		Disk:      enabled,
		WAF:       enabled,
		Cache:     enabled,
		Transform: enabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Presence of {} is the feature flag. omitempty under v2 would drop these
	// because {} is an empty JSON value; omitzero keeps them.
	want := `{"disk":{},"waf":{},"cache":{},"transform":{}}`
	if string(got) != want {
		t.Fatalf("enabled features = %s, want %s", got, want)
	}

	got, err = json.Marshal(LocationFeatures{})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "{}" {
		t.Fatalf("zero features = %s, want {}", got)
	}
}

func TestZeroTimeOmitted(t *testing.T) {
	got, err := json.Marshal(DomainVerificationDNS{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "0001-01-01") {
		t.Fatalf("zero times should be omitted, got %s", got)
	}

	ts := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	got, err = json.Marshal(DomainVerificationDNS{VerifiedAt: ts})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"verifiedAt":"2026-08-01T00:00:00Z"`) {
		t.Fatalf("non-zero verifiedAt missing: %s", got)
	}
	if strings.Contains(string(got), "lastCheckedAt") {
		t.Fatalf("zero lastCheckedAt should be omitted, got %s", got)
	}
}

func TestStatusJSONRoundTrip(t *testing.T) {
	b, err := json.Marshal(Success)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"success"` {
		t.Fatalf("Marshal(Success) = %s", b)
	}
	var s Status
	if err := json.Unmarshal([]byte(`"pending"`), &s); err != nil {
		t.Fatal(err)
	}
	if s != Pending {
		t.Fatalf("Unmarshal pending = %v", s)
	}
}

func TestNilSliceMarshalsEmptyArray(t *testing.T) {
	got, err := json.Marshal(LocationListResult{})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"items":[]}` {
		t.Fatalf("nil items = %s, want {\"items\":[]}", got)
	}
}

func TestEmailAddrUnmarshal(t *testing.T) {
	var a EmailAddr
	if err := json.Unmarshal([]byte(`"user@example.com"`), &a); err != nil {
		t.Fatal(err)
	}
	if a.Email != "user@example.com" || a.Name != "" {
		t.Fatalf("string form = %+v", a)
	}
	if err := json.Unmarshal([]byte(`{"email":"a@b.c","name":"Ada"}`), &a); err != nil {
		t.Fatal(err)
	}
	if a.Email != "a@b.c" || a.Name != "Ada" {
		t.Fatalf("object form = %+v", a)
	}
}
