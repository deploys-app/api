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

	// LookupRepo resolves an owner/name repository to its immutable numeric
	// id and the deploys.app GitHub App installation covering it, so link
	// callers (the console) never ask users for a repository id. It also
	// proves the App is installed on the repository — the lookup fails
	// otherwise.
	LookupRepo(ctx context.Context, m *GitHubLookupRepo) (*GitHubLookupRepoResult, error)

	// GetApp returns public info about the deploys.app GitHub App — currently
	// just the installation URL the console sends users to. Gated by
	// github.link like LookupRepo; it only feeds the link flow.
	GetApp(ctx context.Context, m *GitHubGetApp) (*GitHubAppInfo, error)

	// ListRepos lists the repositories visible to one GitHub App installation,
	// so the console can offer a picker instead of asking users to type
	// owner/name. The installation id comes from GitHub's post-install setup
	// redirect or from an existing link.
	ListRepos(ctx context.Context, m *GitHubListRepos) (*GitHubListReposResult, error)

	// ExchangeToken exchanges a GitHub Actions OIDC token for a short-lived
	// deploys token acting as the service account linked to the repository.
	// It is authenticated by the GitHub token itself, not by the caller's
	// deploys identity.
	ExchangeToken(ctx context.Context, m *GitHubExchangeToken) (*GitHubExchangeTokenResult, error)

	// Notify reports build/deploy progress from a GitHub Actions workflow run
	// so the server can drive GitHub deployment statuses and the PR preview
	// comment as the deploys.app GitHub App. Like ExchangeToken it is
	// authenticated by the workflow's GitHub Actions OIDC token (sent as the
	// bearer token), not by a deploys identity: the token's repository claims
	// are authoritative and the reported sha must match the token's sha claim.
	Notify(ctx context.Context, m *GitHubNotify) (*Empty, error)
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

type GitHubLookupRepo struct {
	Project    string `json:"project" yaml:"project"`
	Repository string `json:"repository" yaml:"repository"` // owner/name
}

func (m *GitHubLookupRepo) Valid() error {
	m.Repository = strings.TrimSpace(m.Repository)

	v := validator.New()

	v.Must(m.Project != "", "project required")
	if v.Must(m.Repository != "", "repository required") {
		v.Must(utf8.RuneCountInString(m.Repository) <= 140, "repository too long")
		v.Must(ReValidGitHubRepository.MatchString(m.Repository), "repository must be in owner/name format")
	}

	return WrapValidate(v)
}

type GitHubLookupRepoResult struct {
	RepositoryID   int64  `json:"repositoryId" yaml:"repositoryId"`
	Repository     string `json:"repository" yaml:"repository"` // canonical owner/name from GitHub
	InstallationID int64  `json:"installationId" yaml:"installationId"`
}

type GitHubGetApp struct {
	Project string `json:"project" yaml:"project"`
}

func (m *GitHubGetApp) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")

	return WrapValidate(v)
}

type GitHubAppInfo struct {
	InstallURL string `json:"installUrl" yaml:"installUrl"` // https://github.com/apps/<slug>/installations/new
}

type GitHubListRepos struct {
	Project        string `json:"project" yaml:"project"`
	InstallationID int64  `json:"installationId" yaml:"installationId"`
}

func (m *GitHubListRepos) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.InstallationID > 0, "installationId required")

	return WrapValidate(v)
}

type GitHubRepoItem struct {
	RepositoryID int64  `json:"repositoryId" yaml:"repositoryId"`
	Repository   string `json:"repository" yaml:"repository"` // owner/name
	Private      bool   `json:"private" yaml:"private"`
}

type GitHubListReposResult struct {
	Items []*GitHubRepoItem `json:"items" yaml:"items"`
}

func (m *GitHubListReposResult) Table() [][]string {
	table := [][]string{
		{"REPOSITORY", "PRIVATE"},
	}
	for _, x := range m.Items {
		table = append(table, []string{
			x.Repository,
			strconv.FormatBool(x.Private),
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

// ReValidGitHubEnvironment validates a notify environment: "production" or
// "pr-<n>" (the transient preview environment for pull request n).
var ReValidGitHubEnvironment = regexp.MustCompile(`^(production|pr-[1-9][0-9]*)$`)

type GitHubNotify struct {
	Event       string `json:"event" yaml:"event"`             // started | success | failure
	Project     string `json:"project" yaml:"project"`         // must match the repository link
	Location    string `json:"location" yaml:"location"`       // deployment location id
	Deployment  string `json:"deployment" yaml:"deployment"`   // deploys.app deployment name
	Environment string `json:"environment" yaml:"environment"` // production | pr-<n>
	PRNumber    int64  `json:"prNumber" yaml:"prNumber"`       // 0 for production
	SHA         string `json:"sha" yaml:"sha"`                 // must equal the token's sha claim
	Ref         string `json:"ref" yaml:"ref"`
	URL         string `json:"url" yaml:"url"`     // success only: the deployed url
	Image       string `json:"image" yaml:"image"` // success only: the deployed image (digest form)
}

func (m *GitHubNotify) Valid() error {
	m.Project = strings.TrimSpace(m.Project)
	m.Location = strings.TrimSpace(m.Location)
	m.Deployment = strings.TrimSpace(m.Deployment)
	m.Environment = strings.TrimSpace(m.Environment)
	m.SHA = strings.TrimSpace(m.SHA)

	v := validator.New()

	v.Must(m.Event == "started" || m.Event == "success" || m.Event == "failure", "event must be started, success, or failure")
	v.Must(m.Project != "", "project required")
	v.Must(m.Location != "", "location required")
	v.Must(m.Deployment != "", "deployment required")
	v.Must(m.SHA != "", "sha required")
	if v.Must(ReValidGitHubEnvironment.MatchString(m.Environment), "environment must be production or pr-<n>") {
		if m.Environment == "production" {
			v.Must(m.PRNumber == 0, "prNumber must be 0 for production")
		} else {
			v.Mustf(m.Environment == "pr-"+strconv.FormatInt(m.PRNumber, 10), "environment must match prNumber (pr-%d)", m.PRNumber)
		}
	}

	return WrapValidate(v)
}
