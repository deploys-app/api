package api

import (
	"strings"
	"testing"
)

// TestDiskDeleteValid guards that DiskDelete.Valid() validates the name the same
// way as DiskCreate/DiskUpdate: a structured ValidateError (not a bare error)
// for an over-length name, and rejection of names shorter than MinNameLength
// (the name regex alone allows 2 chars, but MinNameLength is 3).
func TestDiskDeleteValid(t *testing.T) {
	base := DiskDelete{Project: "p", Location: "gke", Name: "mydisk"}
	if err := base.Valid(); err != nil {
		t.Fatalf("valid DiskDelete rejected: %v", err)
	}

	// over-length name: the structured length message, not the old "name invalid".
	long := base
	long.Name = strings.Repeat("a", MaxNameLength+1)
	err := long.Valid()
	if err == nil {
		t.Fatal("expected an over-length name to be rejected")
	}
	if !strings.Contains(err.Error(), "name must have length between") {
		t.Fatalf("over-length DiskDelete error %q is not the structured length validation", err.Error())
	}

	// name shorter than MinNameLength (matches the regex but is too short) is
	// rejected — consistent with DiskCreate, which the old upper-bound-only check
	// allowed through.
	short := base
	short.Name = strings.Repeat("a", MinNameLength-1)
	if err := short.Valid(); err == nil {
		t.Fatalf("expected a name shorter than MinNameLength (%d) to be rejected", MinNameLength)
	}
}
