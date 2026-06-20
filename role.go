package api

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/asaskevich/govalidator"
	"github.com/moonrhythm/validator"
)

var permissions = []string{
	"*",
	"project.*",
	"project.get",
	"project.delete",
	"role.*",
	"role.create",
	"role.list",
	"role.get",
	"role.delete",
	"role.bind",
	"deployment.*",
	"deployment.deploy",
	"deployment.list",
	"deployment.get",
	"deployment.delete",
	"domain.*",
	"domain.create",
	"domain.list",
	"domain.get",
	"domain.delete",
	"domain.purgecache",
	"route.*",
	"route.create",
	"route.list",
	"route.get",
	"route.delete",
	"pullsecret.*",
	"pullsecret.create",
	"pullsecret.list",
	"pullsecret.get",
	"pullsecret.delete",
	"disk.*",
	"disk.create",
	"disk.update",
	"disk.list",
	"disk.get",
	"disk.delete",
	"workloadidentity.*",
	"workloadidentity.create",
	"workloadidentity.list",
	"workloadidentity.get",
	"workloadidentity.delete",
	"database.*",
	"database.create",
	"database.list",
	"database.get",
	"database.delete",
	"serviceaccount.*",
	"serviceaccount.create",
	"serviceaccount.list",
	"serviceaccount.get",
	"serviceaccount.delete",
	"serviceaccount.key.*",
	"serviceaccount.key.create",
	"serviceaccount.key.delete",
	"email.*",
	"email.send",
	"email.list",
	"dropbox.*",
	"dropbox.upload",
	"dropbox.list",
	"site.*",
	"site.publish",
	"registry.*",
	"registry.push",
	"registry.pull",
	"registry.list",
	"registry.get",
	"envgroup.*",
	"envgroup.create",
	"envgroup.update",
	"envgroup.list",
	"envgroup.get",
	"envgroup.delete",
	"waf.*",
	"waf.get",
	"waf.list",
	"waf.set",
	"waf.delete",
	"cache.*",
	"cache.get",
	"cache.list",
	"cache.set",
	"cache.delete",
	"auditlog.*",
	"auditlog.list",
	"github.*",
	"github.link",
	"github.unlink",
	"github.update",
	"github.list",
	"scheduler.*",
	"scheduler.create",
	"scheduler.update",
	"scheduler.get",
	"scheduler.list",
	"scheduler.delete",
	"scheduler.run",
	"notification.*",
	"notification.create",
	"notification.update",
	"notification.get",
	"notification.list",
	"notification.delete",
	"notification.test",
	"notification.pull",
}

func Permissions() []string {
	xs := make([]string, len(permissions))
	copy(xs, permissions)
	return xs
}

// IsPublicBindablePermission reports whether permission p is safe to grant to a
// public pseudo-principal (allUsers or allAuthenticatedUsers).
//
// A public binding is effectively held by everyone — including unauthenticated
// callers — so a permission may be granted publicly only when it both (a) cannot
// change data and (b) does not expose sensitive material. That admits the read
// actions (".get" / ".list") plus registry.pull (anonymous image pulls are a
// legitimate use case), but excludes:
//   - any write action (create/update/delete/deploy/bind/set/send/upload/
//     publish/purgecache/link/unlink/…) and any wildcard ("*", "<resource>.*",
//     which subsume writes); and
//   - pullsecret.get, which returns the pull-secret value and would leak
//     registry credentials to anonymous callers.
//
// The classification is intentionally fail-safe: a permission is public-bindable
// only when it positively matches a known-safe action, so an unrecognized or
// future permission defaults to NOT public-bindable. A new mutating or sensitive
// permission therefore can never silently slip into a public binding before this
// list is updated.
func IsPublicBindablePermission(p string) bool {
	switch p {
	case "pullsecret.get":
		// Read-only, but the response carries the secret value — never expose it
		// to a public principal.
		return false
	case "notification.get", "notification.list", "notification.pull":
		// notification.get/.list carry channel URLs (e.g. internal Discord
		// webhooks) and notification.pull streams a project's change events —
		// never expose either to a public principal.
		return false
	case "registry.pull":
		// Pulls image blobs; mutates nothing, and public pull is a legitimate
		// use case (public registries).
		return true
	}
	if p == "*" || strings.HasSuffix(p, ".*") {
		return false
	}
	return strings.HasSuffix(p, ".get") || strings.HasSuffix(p, ".list")
}

type Role interface {
	// Create requires the `role.create` permission.
	Create(ctx context.Context, m *RoleCreate) (*Empty, error)
	// List requires the `role.list` permission.
	List(ctx context.Context, m *RoleList) (*RoleListResult, error)
	// Get requires the `role.get` permission.
	Get(ctx context.Context, m *RoleGet) (*RoleGetResult, error)
	// Delete requires the `role.delete` permission.
	Delete(ctx context.Context, m *RoleDelete) (*Empty, error)
	// Grant requires the `role.bind` permission.
	Grant(ctx context.Context, m *RoleGrant) (*Empty, error)
	// Revoke requires the `role.bind` permission.
	Revoke(ctx context.Context, m *RoleRevoke) (*Empty, error)
	// Users requires the `role.list` permission.
	Users(ctx context.Context, m *RoleUsers) (*RoleUsersResult, error)
	// Bind requires the `role.bind` permission.
	Bind(ctx context.Context, m *RoleBind) (*Empty, error)
	// Permissions requires authentication only (no specific permission; returns the static permission catalog).
	Permissions(ctx context.Context, _ *Empty) ([]string, error)
}

type RoleCreate struct {
	Project     string   `json:"project" yaml:"project"` // project sid
	Role        string   `json:"role" yaml:"role"`       // role sid
	Name        string   `json:"name" yaml:"name"`       // role name (free text)
	Permissions []string `json:"permissions" yaml:"permissions"`
}

func (m *RoleCreate) Valid() error {
	m.Role = strings.TrimSpace(m.Role)
	m.Name = strings.TrimSpace(m.Name)

	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Role != "owner", "not allow to edit owner role")
	v.Must(ReValidSID.MatchString(m.Role), "role invalid")
	{
		cnt := utf8.RuneCountInString(m.Role)
		v.Must(cnt >= 3 && cnt <= 20, "role must have length between 3-20 characters")
	}
	v.Must(utf8.ValidString(m.Name), "name invalid")
	{
		cnt := utf8.RuneCountInString(m.Name)
		v.Must(cnt >= 3 && cnt <= 64, "name must have length between 3-64 characters")
	}

	return WrapValidate(v)
}

type RoleGet struct {
	Project string `json:"project" yaml:"project"` // project sid
	Role    string `json:"role" yaml:"role"`       // role sid
}

type RoleGetResult struct {
	Role        string    `json:"role" yaml:"role"`       // role sid
	Project     string    `json:"project" yaml:"project"` // project sid
	Name        string    `json:"name" yaml:"name"`       // role name
	Permissions []string  `json:"permissions" yaml:"permissions"`
	CreatedAt   time.Time `json:"createdAt" yaml:"createdAt"`
}

func (m *RoleGetResult) Table() [][]string {
	table := [][]string{
		{"ROLE", "NAME", "AGE"},
		{
			m.Role,
			m.Name,
			age(m.CreatedAt),
		},
	}
	return table
}

type RoleList struct {
	Project string // project sid
}

type RoleListResult struct {
	Project string          `json:"project" yaml:"project"`
	Items   []*RoleListItem `json:"items" yaml:"items"`
}

func (m *RoleListResult) Table() [][]string {
	table := [][]string{
		{"ROLE", "NAME", "AGE"},
	}
	for _, x := range m.Items {
		table = append(table, []string{
			x.Role,
			x.Name,
			age(x.CreatedAt),
		})
	}
	return table
}

type RoleListItem struct {
	Role        string    `json:"role" yaml:"role"` // role sid
	Name        string    `json:"name" yaml:"name"` // role name
	Permissions []string  `json:"permissions" yaml:"permissions"`
	CreatedAt   time.Time `json:"createdAt" yaml:"createdAt"`
	CreatedBy   string    `json:"createdBy" yaml:"createdBy"`
}

type RoleDelete struct {
	Project string `json:"project" yaml:"project"`
	Role    string `json:"role" yaml:"role"`
}

func (m *RoleDelete) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Role != "", "role required")

	return WrapValidate(v)
}

type RoleGrant struct {
	Project string `json:"project" yaml:"project"` // project sid
	Role    string `json:"role" yaml:"role"`       // role sid
	Email   string `json:"email" yaml:"email"`     // user email
}

func (m *RoleGrant) Valid() error {
	m.Email = strings.TrimSpace(m.Email)

	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(ReValidSID.MatchString(m.Role), "role invalid")
	cnt := utf8.RuneCountInString(m.Role)
	v.Must(cnt >= 6 && cnt <= 20, "role must have length between 6-20 characters")
	v.Must(m.Email != "", "email required")
	v.Must(govalidator.IsEmail(m.Email), "email invalid")

	return WrapValidate(v)
}

type RoleRevoke struct {
	Project string `json:"project" yaml:"project"` // project sid
	Role    string `json:"role" yaml:"role"`       // role sid
	Email   string `json:"email" yaml:"email"`     // user email
}

func (m *RoleRevoke) Valid() error {
	m.Email = strings.TrimSpace(m.Email)

	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(ReValidSID.MatchString(m.Role), "role invalid")
	cnt := utf8.RuneCountInString(m.Role)
	v.Must(cnt >= 6 && cnt <= 20, "role must have length between 6-20 characters")
	v.Must(m.Email != "", "email required")
	v.Must(govalidator.IsEmail(m.Email), "email invalid")

	return WrapValidate(v)
}

type RoleUsers struct {
	Project string `json:"project" yaml:"project"` // project sid
}

func (m *RoleUsers) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")

	return WrapValidate(v)
}

type RoleUsersResult struct {
	Project string           `json:"project" yaml:"project"`
	Items   []*RoleUsersItem `json:"items" yaml:"items"`
	Users   []*RoleUsersItem `json:"users" yaml:"users"`
}

func (m *RoleUsersResult) Table() [][]string {
	table := [][]string{
		{"EMAIL", "ROLE"},
	}
	for _, u := range m.Items {
		for _, r := range u.Roles {
			table = append(table, []string{
				u.Email,
				r,
			})
		}
	}
	return table
}

type RoleUsersItem struct {
	Email string   `json:"email" yaml:"email"`
	Roles []string `json:"roles" yaml:"roles"`
}

type RoleBind struct {
	Project string   `json:"project" yaml:"project"`
	Email   string   `json:"email" yaml:"email"`
	Roles   []string `json:"roles" yaml:"roles"`
}
