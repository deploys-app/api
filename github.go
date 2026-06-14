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
	// Link requires the `github.link` permission.
	Link(ctx context.Context, m *GitHubLink) (*Empty, error)
	// Unlink requires the `github.unlink` permission.
	Unlink(ctx context.Context, m *GitHubUnlink) (*Empty, error)
	// Update changes an existing link's service account, deploy trigger, and
	// production branch in place. The repository id and installation id are
	// immutable — changing the repository means a new link.
	// Update requires the `github.update` permission.
	Update(ctx context.Context, m *GitHubUpdate) (*Empty, error)
	// List requires the `github.list` permission.
	List(ctx context.Context, m *GitHubList) (*GitHubListResult, error)

	// LookupRepo resolves an owner/name repository to its immutable numeric
	// id and the deploys.app GitHub App installation covering it, so link
	// callers (the console) never ask users for a repository id. It also
	// proves the App is installed on the repository — the lookup fails
	// otherwise.
	// LookupRepo requires the `github.link` permission.
	LookupRepo(ctx context.Context, m *GitHubLookupRepo) (*GitHubLookupRepoResult, error)

	// GetApp returns public info about the deploys.app GitHub App — currently
	// just the installation URL the console sends users to. Gated by
	// github.link like LookupRepo; it only feeds the link flow.
	// GetApp requires the `github.link` permission.
	GetApp(ctx context.Context, m *GitHubGetApp) (*GitHubAppInfo, error)

	// ListRepos lists the repositories visible to one GitHub App installation,
	// so the console can offer a picker instead of asking users to type
	// owner/name. The installation id comes from GitHub's post-install setup
	// redirect or from an existing link.
	// ListRepos requires the `github.link` permission.
	ListRepos(ctx context.Context, m *GitHubListRepos) (*GitHubListReposResult, error)

	// ExchangeToken exchanges a GitHub Actions OIDC token for a short-lived
	// deploys token acting as the service account linked to the repository.
	// It is authenticated by the GitHub token itself, not by the caller's
	// deploys identity.
	// ExchangeToken requires a GitHub Actions OIDC token (no project permission).
	ExchangeToken(ctx context.Context, m *GitHubExchangeToken) (*GitHubExchangeTokenResult, error)

	// Notify reports build/deploy progress from a GitHub Actions workflow run
	// so the server can drive GitHub deployment statuses and the PR preview
	// comment as the deploys.app GitHub App. Like ExchangeToken it is
	// authenticated by the workflow's GitHub Actions OIDC token (sent as the
	// bearer token), not by a deploys identity: the token's repository claims
	// are authoritative and the reported sha must match the token's sha claim.
	// Notify requires a GitHub Actions OIDC token (no project permission).
	Notify(ctx context.Context, m *GitHubNotify) (*Empty, error)

	// AddInstallation remembers a GitHub App installation id for a project.
	// The console calls this when GitHub's post-install setup redirect returns
	// with ?installation_id= so users do not have to re-install to see their
	// repo list later.
	AddInstallation(ctx context.Context, m *GitHubAddInstallation) (*Empty, error)

	// ListInstallations returns all GitHub App installation ids recorded for a
	// project, so the console can populate a picker without asking users for an
	// installation id.
	ListInstallations(ctx context.Context, m *GitHubListInstallations) (*GitHubListInstallationsResult, error)
}

// ReValidGitHubRepository validates an "owner/name" GitHub repository full name.
var ReValidGitHubRepository = regexp.MustCompile(`^[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+$`)

type GitHubLink struct {
	Project        string `json:"project" yaml:"project"`
	RepositoryID   int64  `json:"repositoryId" yaml:"repositoryId"`     // immutable github repository id
	Repository     string `json:"repository" yaml:"repository"`         // owner/name, display only
	InstallationID int64  `json:"installationId" yaml:"installationId"` // github app installation id, optional
	ServiceAccount string `json:"serviceAccount" yaml:"serviceAccount"` // service account sid in the project

	// ProductionBranch selects which branch deploys to production for the "all"
	// and "branch" triggers — push-event GitHub OIDC tokens whose ref is this
	// branch are accepted; others are rejected. Empty means any branch. Ignored
	// by the "pr" trigger (which never deploys a branch).
	ProductionBranch string `json:"productionBranch" yaml:"productionBranch"`

	// Trigger selects which workflow runs deploy: "all" (push to the production
	// branch + pull-request previews, the default), "branch" (push only, no
	// previews), or "pr" (previews only, no branch ever deploys).
	Trigger GitHubTrigger `json:"trigger" yaml:"trigger"`
}

func (m *GitHubLink) Valid() error {
	m.Repository = strings.TrimSpace(m.Repository)
	m.ServiceAccount = strings.TrimSpace(m.ServiceAccount)
	m.ProductionBranch = strings.TrimSpace(m.ProductionBranch)

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
	if m.ProductionBranch != "" { // optional, empty = no restriction
		v.Must(utf8.RuneCountInString(m.ProductionBranch) <= 255, "productionBranch too long")
		v.Must(!strings.ContainsAny(m.ProductionBranch, " \t\n\r"), "productionBranch invalid")
		v.Must(!strings.Contains(m.ProductionBranch, ".."), "productionBranch invalid")
		v.Must(!strings.HasPrefix(m.ProductionBranch, "/") && !strings.HasSuffix(m.ProductionBranch, "/"), "productionBranch invalid")
		v.Must(!strings.HasPrefix(m.ProductionBranch, "-"), "productionBranch invalid")
		v.Must(!strings.HasPrefix(m.ProductionBranch, "refs/"), "productionBranch invalid")
	}
	if v.Must(m.Trigger.Valid(), "trigger must be all, branch, or pr") {
		v.Must(m.Trigger != GitHubTriggerPR || m.ProductionBranch == "", "productionBranch must be empty for the pr trigger")
	}

	return WrapValidate(v)
}

// GitHubUpdate edits an existing link in place. RepositoryID identifies the
// link; the service account, deploy trigger, and production branch are the
// mutable fields. The repository's owner/name and installation id are immutable
// and so are not part of this request.
type GitHubUpdate struct {
	Project          string        `json:"project" yaml:"project"`
	RepositoryID     int64         `json:"repositoryId" yaml:"repositoryId"`     // immutable github repository id, identifies the link
	ServiceAccount   string        `json:"serviceAccount" yaml:"serviceAccount"` // service account sid in the project
	ProductionBranch string        `json:"productionBranch" yaml:"productionBranch"`
	Trigger          GitHubTrigger `json:"trigger" yaml:"trigger"`
}

func (m *GitHubUpdate) Valid() error {
	m.ServiceAccount = strings.TrimSpace(m.ServiceAccount)
	m.ProductionBranch = strings.TrimSpace(m.ProductionBranch)

	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.RepositoryID > 0, "repositoryId required")
	if v.Must(m.ServiceAccount != "", "serviceAccount required") {
		v.Mustf(ReValidSID.MatchString(m.ServiceAccount), "serviceAccount invalid %s", ReValidSIDStr)
		cnt := utf8.RuneCountInString(m.ServiceAccount)
		v.Must(cnt >= 3 && cnt <= 20, "serviceAccount must have length between 3-20 characters")
	}
	if m.ProductionBranch != "" { // optional, empty = no restriction
		v.Must(utf8.RuneCountInString(m.ProductionBranch) <= 255, "productionBranch too long")
		v.Must(!strings.ContainsAny(m.ProductionBranch, " \t\n\r"), "productionBranch invalid")
		v.Must(!strings.Contains(m.ProductionBranch, ".."), "productionBranch invalid")
		v.Must(!strings.HasPrefix(m.ProductionBranch, "/") && !strings.HasSuffix(m.ProductionBranch, "/"), "productionBranch invalid")
		v.Must(!strings.HasPrefix(m.ProductionBranch, "-"), "productionBranch invalid")
		v.Must(!strings.HasPrefix(m.ProductionBranch, "refs/"), "productionBranch invalid")
	}
	if v.Must(m.Trigger.Valid(), "trigger must be all, branch, or pr") {
		v.Must(m.Trigger != GitHubTriggerPR || m.ProductionBranch == "", "productionBranch must be empty for the pr trigger")
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
	RepositoryID        int64         `json:"repositoryId" yaml:"repositoryId"`
	Repository          string        `json:"repository" yaml:"repository"`
	InstallationID      int64         `json:"installationId" yaml:"installationId"`
	ServiceAccount      string        `json:"serviceAccount" yaml:"serviceAccount"`
	ServiceAccountEmail string        `json:"serviceAccountEmail" yaml:"serviceAccountEmail"`
	ProductionBranch    string        `json:"productionBranch" yaml:"productionBranch"` // empty = any branch (all/branch triggers)
	Trigger             GitHubTrigger `json:"trigger" yaml:"trigger"`                   // all | branch | pr
	CreatedAt           time.Time     `json:"createdAt" yaml:"createdAt"`
	CreatedBy           string        `json:"createdBy" yaml:"createdBy"`
}

type GitHubListResult struct {
	Project string            `json:"project" yaml:"project"`
	Items   []*GitHubLinkItem `json:"items" yaml:"items"`
}

func (m *GitHubListResult) Table() [][]string {
	table := [][]string{
		{"REPOSITORY", "REPOSITORY ID", "SERVICE ACCOUNT", "TRIGGER", "BRANCH", "AGE"},
	}
	for _, x := range m.Items {
		branch := x.ProductionBranch
		if branch == "" {
			branch = "-" // any branch (all/branch triggers)
		}
		if !x.Trigger.DeploysBranch() {
			branch = "-" // pr trigger never deploys a branch
		}
		table = append(table, []string{
			x.Repository,
			strconv.FormatInt(x.RepositoryID, 10),
			x.ServiceAccount,
			x.Trigger.String(),
			branch,
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

// ReValidGitHubSHA matches a full git object id (SHA-1 or SHA-256). HeadSHA is
// only ever rendered or used as a GitHub deployment ref, so it must be a real
// commit id and never an arbitrary commitish (a branch name, "HEAD~3", ...).
var ReValidGitHubSHA = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

type GitHubNotify struct {
	Event       string `json:"event" yaml:"event"`             // started | success | failure
	Project     string `json:"project" yaml:"project"`         // must match the repository link
	Location    string `json:"location" yaml:"location"`       // deployment location id
	Deployment  string `json:"deployment" yaml:"deployment"`   // deploys.app deployment name
	Environment string `json:"environment" yaml:"environment"` // production | pr-<n>
	PRNumber    int64  `json:"prNumber" yaml:"prNumber"`       // 0 for production
	SHA         string `json:"sha" yaml:"sha"`                 // must equal the token's sha claim (on PRs, the refs/pull/N/merge merge commit)
	// HeadSHA is the contributor's pushed commit (github.event.pull_request.head.sha).
	// Empty on push/production runs, where SHA already is the pushed tip. It is
	// used only for display (the PR comment) and as the GitHub deployment ref —
	// never for authorization — so the anti-spoof binding stays on SHA.
	HeadSHA string `json:"headSha" yaml:"headSha"`
	Ref     string `json:"ref" yaml:"ref"`
	URL     string `json:"url" yaml:"url"`     // success only: the deployed url
	Image   string `json:"image" yaml:"image"` // success only: the deployed image (digest form)
}

func (m *GitHubNotify) Valid() error {
	m.Project = strings.TrimSpace(m.Project)
	m.Location = strings.TrimSpace(m.Location)
	m.Deployment = strings.TrimSpace(m.Deployment)
	m.Environment = strings.TrimSpace(m.Environment)
	m.SHA = strings.TrimSpace(m.SHA)
	m.HeadSHA = strings.ToLower(strings.TrimSpace(m.HeadSHA))

	v := validator.New()

	v.Must(m.Event == "started" || m.Event == "success" || m.Event == "failure", "event must be started, success, or failure")
	v.Must(m.Project != "", "project required")
	v.Must(m.Location != "", "location required")
	v.Must(m.Deployment != "", "deployment required")
	v.Must(m.SHA != "", "sha required")
	v.Must(m.HeadSHA == "" || ReValidGitHubSHA.MatchString(m.HeadSHA), "headSha must be a commit sha")
	if v.Must(ReValidGitHubEnvironment.MatchString(m.Environment), "environment must be production or pr-<n>") {
		if m.Environment == "production" {
			v.Must(m.PRNumber == 0, "prNumber must be 0 for production")
		} else {
			v.Mustf(m.Environment == "pr-"+strconv.FormatInt(m.PRNumber, 10), "environment must match prNumber (pr-%d)", m.PRNumber)
		}
	}

	return WrapValidate(v)
}

// GitHubAddInstallation is the request type for GitHub.AddInstallation.
// Both project and installationId are required.
type GitHubAddInstallation struct {
	Project        string `json:"project" yaml:"project"`
	InstallationID int64  `json:"installationId" yaml:"installationId"`
}

func (m *GitHubAddInstallation) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.InstallationID > 0, "installationId required")

	return WrapValidate(v)
}

// GitHubListInstallations is the request type for GitHub.ListInstallations.
type GitHubListInstallations struct {
	Project string `json:"project" yaml:"project"`
}

func (m *GitHubListInstallations) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")

	return WrapValidate(v)
}

// GitHubInstallationItem holds a single recorded GitHub App installation id.
type GitHubInstallationItem struct {
	InstallationID int64     `json:"installationId" yaml:"installationId"`
	CreatedAt      time.Time `json:"createdAt" yaml:"createdAt"`
}

// GitHubListInstallationsResult is the response type for GitHub.ListInstallations.
type GitHubListInstallationsResult struct {
	Items []*GitHubInstallationItem `json:"items" yaml:"items"`
}

func (m *GitHubListInstallationsResult) Table() [][]string {
	table := [][]string{
		{"INSTALLATION ID", "AGE"},
	}
	for _, x := range m.Items {
		table = append(table, []string{
			strconv.FormatInt(x.InstallationID, 10),
			age(x.CreatedAt),
		})
	}
	return table
}
