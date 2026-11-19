package client

import (
	"strings"
	"testing"

	json "encoding/json/v2"
)

func TestDropboxOptionalIntsOmitted(t *testing.T) {
	got, err := json.Marshal(DropboxCreateUploadURLOptions{Project: "p"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	for _, k := range []string{"minSize", "maxSize", "ttl", "expires"} {
		if strings.Contains(s, k) {
			t.Fatalf("zero %s should be omitted, got %s", k, s)
		}
	}
	if s != `{"project":"p"}` {
		t.Fatalf("got %s", s)
	}
}

func TestSiteManifestDeterministic(t *testing.T) {
	m := siteManifest{
		Environment: "production",
		Files: map[string]siteManifestEntry{
			"z.txt":  {Blob: "b", CT: "text/plain", Cache: "html"},
			"a.html": {Blob: "a", CT: "text/html", Cache: "html"},
		},
	}
	var prev string
	for range 20 {
		b, err := json.Marshal(m, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		if prev == "" {
			prev = string(b)
			continue
		}
		if string(b) != prev {
			t.Fatalf("non-deterministic marshal:\n %s\n %s", prev, b)
		}
	}
	if !strings.Contains(prev, `"a.html"`) || !strings.Contains(prev, `"z.txt"`) {
		t.Fatalf("missing files: %s", prev)
	}
	// Sorted map keys: a.html before z.txt.
	if i, j := strings.Index(prev, `"a.html"`), strings.Index(prev, `"z.txt"`); i < 0 || j < 0 || i > j {
		t.Fatalf("files keys not sorted: %s", prev)
	}
}
