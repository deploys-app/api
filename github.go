package api

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/moonrhythm/validator"
)

type GitHub interface {
	Link(ctx context.Context, m *GitHubLink) (*Empty, error)
	Unlink(ctx context.Context, m *GitHubUnlink) (*Empty, error)
	List(ctx context.Context, m *GitHubList) (*GitHubListResult, error)

	// ExchangeToken exchanges a GitHub Actions OIDC token for a short-lived
	// deploys token acting as the service account linked to the repository.
	// It is authenticated by the GitHub token itself, not by the caller's
	// deploys identity.
	ExchangeToken(ctx context.Context, m *GitHubExchangeToken) (*GitHubExchangeTokenResult, error)
}

// ReValidGitHubRepository validates an "owner/name" GitHub repository full name.
var ReValidGitHubRepository = regexp.MustCompile(`^[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+$`)

type GitHubLink struct {
	Project        string `json:"project" yaml:"project"`
	RepositoryID   int64  `json:"repositoryId" yaml:"repositoryId"`     // immutable github repository id
	Repository     string `json:"repository" yaml:"repository"`         // owner/name, display only
	InstallationID int64  `json:"installationId" yaml:"installationId"` // github app installation id, optional
	ServiceAccount string `json:"serviceAccount" yaml:"serviceAccount"` // service account sid in the project
}

func (m *GitHubLink) Valid() error {
	m.Repository = strings.TrimSpace(m.Repository)
	m.ServiceAccount = strings.TrimSpace(m.ServiceAccount)

	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.RepositoryID > 0, "repositoryId required")
	if v.Must(m.Repository != "", "repository required") {
		v.Must(utf8.RuneCountInString(m.Repository) <= 140, "repository too long")
		v.Must(ReValidGitHubRepository.MatchString(m.Repository), "repository must be in owner/name format")
	}
	v.Must(m.InstallationID >= 0, "installationId invalid")
	if v.Must(m.ServiceAccount != "", "serviceAccount required") {
		v.Mustf(ReValidSID.MatchString(m.ServiceAccount), "serviceAccount invalid %s", ReValidSIDStr)
		cnt := utf8.RuneCountInString(m.ServiceAccount)
		v.Must(cnt >= 3 && cnt <= 20, "serviceAccount must have length between 3-20 characters")
	}

	return WrapValidate(v)
}

type GitHubUnlink struct {
	Project      string `json:"project" yaml:"project"`
	RepositoryID int64  `json:"repositoryId" yaml:"repositoryId"`
}

func (m *GitHubUnlink) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.RepositoryID > 0, "repositoryId required")

	return WrapValidate(v)
}

type GitHubList struct {
	Project string `json:"project" yaml:"project"`
}

func (m *GitHubList) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")

	return WrapValidate(v)
}

type GitHubLinkItem struct {
	RepositoryID        int64     `json:"repositoryId" yaml:"repositoryId"`
	Repository          string    `json:"repository" yaml:"repository"`
	InstallationID      int64     `json:"installationId" yaml:"installationId"`
	ServiceAccount      string    `json:"serviceAccount" yaml:"serviceAccount"`
	ServiceAccountEmail string    `json:"serviceAccountEmail" yaml:"serviceAccountEmail"`
	CreatedAt           time.Time `json:"createdAt" yaml:"createdAt"`
	CreatedBy           string    `json:"createdBy" yaml:"createdBy"`
}

type GitHubListResult struct {
	Project string            `json:"project" yaml:"project"`
	Items   []*GitHubLinkItem `json:"items" yaml:"items"`
}

func (m *GitHubListResult) Table() [][]string {
	table := [][]string{
		{"REPOSITORY", "REPOSITORY ID", "SERVICE ACCOUNT", "AGE"},
	}
	for _, x := range m.Items {
		table = append(table, []string{
			x.Repository,
			strconv.FormatInt(x.RepositoryID, 10),
			x.ServiceAccount,
			age(x.CreatedAt),
		})
	}
	return table
}

type GitHubExchangeToken struct {
	Token string `json:"token" yaml:"token"` // github actions oidc token (jwt)
}

func (m *GitHubExchangeToken) Valid() error {
	m.Token = strings.TrimSpace(m.Token)

	v := validator.New()

	v.Must(m.Token != "", "token required")

	return WrapValidate(v)
}

type GitHubExchangeTokenResult struct {
	Token     string    `json:"token" yaml:"token"`
	ExpiresAt time.Time `json:"expiresAt" yaml:"expiresAt"`
}
