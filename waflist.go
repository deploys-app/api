package api

import (
	"context"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/moonrhythm/validator"
)

// WAFLists manages a project's named WAF lists: reusable IP/CIDR sets
// referenced from WAF rule expressions and limit filters via the platform
// macro ipInList(<field>, "<name>"). A list is project-scoped data — it has
// no location and no materialization lifecycle of its own; the apiserver
// expands references into pure engine CEL when it materializes each
// referencing zone, so waf.get always returns the unexpanded form.
//
// (The Go type WAFList is already taken by the waf.list request in waf.go,
// hence the plural interface name and the mechanical WAFListList /
// WAFListListResult request/result names.)
type WAFLists interface {
	// Set requires the `wafList.set` permission. Create-or-replace by name,
	// whole-entries replace, all-or-nothing (mirrors waf.set).
	Set(ctx context.Context, m *WAFListSet) (*Empty, error)
	// Get requires the `wafList.get` permission.
	Get(ctx context.Context, m *WAFListGet) (*WAFListItem, error)
	// List requires the `wafList.list` permission.
	List(ctx context.Context, m *WAFListList) (*WAFListListResult, error)
	// Delete requires the `wafList.delete` permission. Refused while any of
	// the project's zones references the list (the error names the referents).
	Delete(ctx context.Context, m *WAFListDelete) (*Empty, error)
}

// WAFListType is the entry type of a list. v1 supports only "ip"
// (IPv4/IPv6 addresses and CIDRs). "" normalizes to "ip". The type is
// immutable after creation (a type change would silently change what every
// referencing macro means).
type WAFListType string

const WAFListTypeIP WAFListType = "ip"

type WAFListSet struct {
	Project     string      `json:"project" yaml:"project"`
	Name        string      `json:"name" yaml:"name"`
	Description string      `json:"description" yaml:"description"`
	Type        WAFListType `json:"type" yaml:"type"`       // "" = ip
	Entries     []string    `json:"entries" yaml:"entries"` // IPs / CIDRs; normalized server-side
}

func (m *WAFListSet) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	if m.Type == "" {
		m.Type = WAFListTypeIP
	}

	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(ReValidName.MatchString(m.Name), "name invalid: "+ReValidNameDesc)
	{
		cnt := utf8.RuneCountInString(m.Name)
		v.Mustf(cnt >= MinNameLength && cnt <= MaxNameLength, "name must have length between %d-%d characters", MinNameLength, MaxNameLength)
	}
	v.Must(m.Type == WAFListTypeIP, "type invalid (want ip)")
	v.Mustf(utf8.RuneCountInString(m.Description) <= WAFMaxMessageLength, "description must not exceed %d characters", WAFMaxMessageLength)

	v.Mustf(len(m.Entries) <= WAFListMaxEntries, "entries must not exceed %d entries", WAFListMaxEntries)
	for i := range m.Entries {
		m.Entries[i] = strings.TrimSpace(m.Entries[i])
		e := m.Entries[i]
		ref := "#" + strconv.Itoa(i)

		if e == "" {
			v.Mustf(false, "entry %s: required", ref)
			continue
		}
		v.Mustf(utf8.RuneCountInString(e) <= WAFListMaxEntryLength, "entry %s: must not exceed %d characters", ref, WAFListMaxEntryLength)
		v.Mustf(validWAFListEntry(e), "entry %s: %q is not an ip address or cidr", ref, e)
	}
	// Duplicate detection happens server-side post-normalization (the client
	// cannot canonicalize IPv6 text reliably across mirrors of this helper).

	return WrapValidate(v)
}

// validWAFListEntry reports whether e is a v1 "ip" list entry: an IPv4/IPv6
// address or CIDR. Zoned addresses are rejected (a zone is host-local and
// meaningless at the edge).
func validWAFListEntry(e string) bool {
	if strings.Contains(e, "/") {
		_, err := netip.ParsePrefix(e)
		return err == nil
	}
	addr, err := netip.ParseAddr(e)
	return err == nil && addr.Zone() == ""
}

type WAFListGet struct {
	Project string `json:"project" yaml:"project"`
	Name    string `json:"name" yaml:"name"`
}

func (m *WAFListGet) Valid() error {
	m.Name = strings.TrimSpace(m.Name)

	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Name != "", "name required")

	return WrapValidate(v)
}

type WAFListList struct {
	Project string `json:"project" yaml:"project"`
}

func (m *WAFListList) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")

	return WrapValidate(v)
}

type WAFListDelete struct {
	Project string `json:"project" yaml:"project"`
	Name    string `json:"name" yaml:"name"`
}

func (m *WAFListDelete) Valid() error {
	m.Name = strings.TrimSpace(m.Name)

	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Name != "", "name required")

	return WrapValidate(v)
}

type WAFListItem struct {
	Project     string      `json:"project" yaml:"project"`
	Name        string      `json:"name" yaml:"name"`
	Description string      `json:"description" yaml:"description"`
	Type        WAFListType `json:"type" yaml:"type"`
	Entries     []string    `json:"entries" yaml:"entries"`
	// ReferencedBy lists the project's zones currently referencing this list
	// (location ids, computed by scanning the zones' stored expressions with
	// WAFListRefs). Read-only; what the console shows and what a blocked
	// delete reports.
	ReferencedBy []string  `json:"referencedBy" yaml:"referencedBy"`
	CreatedAt    time.Time `json:"createdAt" yaml:"createdAt"`
	CreatedBy    string    `json:"createdBy" yaml:"createdBy"`
	UpdatedAt    time.Time `json:"updatedAt" yaml:"updatedAt"`
}

func (m *WAFListItem) Table() [][]string {
	table := [][]string{
		wafListTableHeader,
		wafListTableRow(m),
	}
	return table
}

type WAFListListResult struct {
	Project string         `json:"project" yaml:"project"`
	Items   []*WAFListItem `json:"items" yaml:"items"`
}

func (m *WAFListListResult) Table() [][]string {
	table := [][]string{
		wafListTableHeader,
	}
	for _, x := range m.Items {
		table = append(table, wafListTableRow(x))
	}
	return table
}

var wafListTableHeader = []string{"NAME", "TYPE", "ENTRIES", "REFERENCED BY", "AGE"}

func wafListTableRow(x *WAFListItem) []string {
	return []string{
		x.Name,
		string(x.Type),
		strconv.Itoa(len(x.Entries)),
		strings.Join(x.ReferencedBy, ","),
		age(x.CreatedAt),
	}
}
