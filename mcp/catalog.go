package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/deploys-app/api"
	"github.com/deploys-app/api/client"
	"github.com/google/jsonschema-go/jsonschema"
)

// action is one entry in the deploys.app API catalogue. invoke unmarshals the
// raw params into the action's typed request struct and calls the client; the
// client validates the request (Valid()) and performs the HTTP call.
type action struct {
	name        string
	group       string
	desc        string
	readOnly    bool
	destructive bool
	schema      *jsonschema.Schema
	invoke      func(ctx context.Context, raw json.RawMessage) (any, error)
}

type registry struct {
	actions map[string]*action
	list    []*action // registration order, for stable browsing
}

// searchHit is the JSON shape returned by deploys_search_actions.
type searchHit struct {
	Action      string             `json:"action"`
	Group       string             `json:"group"`
	Description string             `json:"description"`
	ReadOnly    bool               `json:"readOnly"`
	Destructive bool               `json:"destructive"`
	InputSchema *jsonschema.Schema `json:"inputSchema,omitempty"`
}

func (a *action) hit() searchHit {
	return searchHit{
		Action:      a.name,
		Group:       a.group,
		Description: a.desc,
		ReadOnly:    a.readOnly,
		Destructive: a.destructive,
		InputSchema: a.schema,
	}
}

func (r *registry) search(query string, limit int) []searchHit {
	q := strings.ToLower(strings.TrimSpace(query))
	terms := strings.Fields(q)

	type scored struct {
		a     *action
		score int
	}
	var matches []scored
	for _, a := range r.list {
		name := strings.ToLower(a.name)
		hay := name + " " + strings.ToLower(a.group) + " " + strings.ToLower(a.desc)

		score := 0
		switch {
		case q == "":
			score = 1 // browse mode: return everything in registration order
		default:
			if strings.Contains(hay, q) {
				score += 5
			}
			for _, t := range terms {
				if strings.Contains(name, t) {
					score += 3
				} else if strings.Contains(hay, t) {
					score++
				}
			}
		}
		if score > 0 {
			matches = append(matches, scored{a, score})
		}
	}

	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].score != matches[j].score {
			return matches[i].score > matches[j].score
		}
		return matches[i].a.name < matches[j].a.name
	})

	if limit > 0 && len(matches) > limit {
		matches = matches[:limit]
	}
	hits := make([]searchHit, len(matches))
	for i, m := range matches {
		hits[i] = m.a.hit()
	}
	return hits
}

// add registers a typed (ctx, *Req) -> (*Res, error) client method. The input
// JSON schema is derived from Req via reflection.
func add[Req, Res any](r *registry, name, group, desc string, readOnly, destructive bool, fn func(context.Context, *Req) (*Res, error)) {
	addAny(r, name, group, desc, readOnly, destructive, func(ctx context.Context, m *Req) (any, error) {
		return fn(ctx, m)
	})
}

// addAny is the core registrar, used directly for the few methods whose return
// type is not a pointer (e.g. role.permissions -> []string).
func addAny[Req any](r *registry, name, group, desc string, readOnly, destructive bool, fn func(context.Context, *Req) (any, error)) {
	schema, err := jsonschema.For[Req](nil)
	if err != nil {
		panic(fmt.Sprintf("deploys-mcp: building schema for %s: %v", name, err))
	}
	a := &action{
		name:        name,
		group:       group,
		desc:        desc,
		readOnly:    readOnly,
		destructive: destructive,
		schema:      schema,
		invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var req Req
			if len(raw) > 0 && string(raw) != "null" {
				if err := json.Unmarshal(raw, &req); err != nil {
					return nil, fmt.Errorf("invalid params: %w", err)
				}
			}
			return fn(ctx, &req)
		},
	}
	if _, dup := r.actions[name]; dup {
		panic("deploys-mcp: duplicate action id " + name)
	}
	r.actions[name] = a
	r.list = append(r.list, a)
}

// buildCatalog registers every user-facing deploys.app action. The privileged
// Collector and Deployer interfaces are intentionally excluded, as are the two
// multipart upload methods (me.uploadKYCDocument, billing.uploadTransferSlip)
// that the JSON client cannot express.
func buildCatalog(c *client.Client) *registry {
	r := &registry{actions: map[string]*action{}}

	// Me
	add(r, "me.get", "Me", "Get the current authenticated account profile.", true, false, c.Me().Get)
	add(r, "me.authorized", "Me", "Check whether the current account is authorized for given permissions.", true, false, c.Me().Authorized)

	// Billing
	add(r, "billing.create", "Billing", "Create a billing account.", false, false, c.Billing().Create)
	add(r, "billing.list", "Billing", "List billing accounts the account can access.", true, false, c.Billing().List)
	add(r, "billing.get", "Billing", "Get a billing account by id.", true, false, c.Billing().Get)
	add(r, "billing.update", "Billing", "Update a billing account.", false, false, c.Billing().Update)
	add(r, "billing.delete", "Billing", "Delete a billing account.", false, true, c.Billing().Delete)
	add(r, "billing.report", "Billing", "Get a usage/cost report for a billing account.", true, false, c.Billing().Report)
	add(r, "billing.skus", "Billing", "List billable SKUs and their prices.", true, false, c.Billing().SKUs)
	add(r, "billing.project", "Billing", "List projects attached to a billing account.", true, false, c.Billing().Project)
	add(r, "billing.listInvoices", "Billing", "List invoices for a billing account.", true, false, c.Billing().ListInvoices)
	add(r, "billing.getInvoice", "Billing", "Get a single invoice by id.", true, false, c.Billing().GetInvoice)
	add(r, "billing.downloadInvoice", "Billing", "Get a download URL/PDF for an invoice.", true, false, c.Billing().DownloadInvoice)

	// Location
	add(r, "location.list", "Location", "List available deployment locations (regions/clusters).", true, false, c.Location().List)
	add(r, "location.get", "Location", "Get details of a deployment location.", true, false, c.Location().Get)

	// Project
	add(r, "project.create", "Project", "Create a project.", false, false, c.Project().Create)
	add(r, "project.get", "Project", "Get a project by id.", true, false, c.Project().Get)
	add(r, "project.list", "Project", "List projects the account can access.", true, false, c.Project().List)
	add(r, "project.update", "Project", "Update a project.", false, false, c.Project().Update)
	add(r, "project.delete", "Project", "Delete a project and all of its resources.", false, true, c.Project().Delete)
	add(r, "project.usage", "Project", "Get current resource usage for a project.", true, false, c.Project().Usage)

	// Role
	add(r, "role.create", "Role", "Create an IAM role in a project.", false, false, c.Role().Create)
	add(r, "role.list", "Role", "List roles in a project.", true, false, c.Role().List)
	add(r, "role.get", "Role", "Get a role and its permissions.", true, false, c.Role().Get)
	add(r, "role.delete", "Role", "Delete a role.", false, true, c.Role().Delete)
	add(r, "role.grant", "Role", "Grant permissions to a role.", false, false, c.Role().Grant)
	add(r, "role.revoke", "Role", "Revoke permissions from a role.", false, true, c.Role().Revoke)
	add(r, "role.users", "Role", "List users bound to roles in a project.", true, false, c.Role().Users)
	add(r, "role.bind", "Role", "Bind a user to a role (assign membership).", false, false, c.Role().Bind)
	addAny(r, "role.permissions", "Role", "List all permission strings that can be assigned to roles.", true, false,
		func(ctx context.Context, m *api.Empty) (any, error) { return c.Role().Permissions(ctx, m) })

	// Deployment
	add(r, "deployment.deploy", "Deployment", "Create or update a deployment (deploy a new revision).", false, false, c.Deployment().Deploy)
	add(r, "deployment.list", "Deployment", "List deployments in a project.", true, false, c.Deployment().List)
	add(r, "deployment.get", "Deployment", "Get a deployment by name.", true, false, c.Deployment().Get)
	add(r, "deployment.revisions", "Deployment", "List revisions of a deployment.", true, false, c.Deployment().Revisions)
	add(r, "deployment.resume", "Deployment", "Resume a paused deployment.", false, false, c.Deployment().Resume)
	add(r, "deployment.pause", "Deployment", "Pause a running deployment (scale to zero).", false, false, c.Deployment().Pause)
	add(r, "deployment.rollback", "Deployment", "Roll a deployment back to a previous revision.", false, false, c.Deployment().Rollback)
	add(r, "deployment.delete", "Deployment", "Delete a deployment.", false, true, c.Deployment().Delete)
	add(r, "deployment.metrics", "Deployment", "Get runtime metrics (CPU/memory/etc.) for a deployment.", true, false, c.Deployment().Metrics)

	// Domain
	add(r, "domain.create", "Domain", "Add a custom domain to a project.", false, false, c.Domain().Create)
	add(r, "domain.get", "Domain", "Get a domain and its certificate/status.", true, false, c.Domain().Get)
	add(r, "domain.list", "Domain", "List domains in a project.", true, false, c.Domain().List)
	add(r, "domain.delete", "Domain", "Delete a domain.", false, true, c.Domain().Delete)
	add(r, "domain.purgeCache", "Domain", "Purge the CDN cache for a domain.", false, false, c.Domain().PurgeCache)

	// Route
	add(r, "route.create", "Route", "Create a route mapping a domain/path to a deployment.", false, false, c.Route().Create)
	add(r, "route.createV2", "Route", "Create a route (v2 schema).", false, false, c.Route().CreateV2)
	add(r, "route.get", "Route", "Get a route by id.", true, false, c.Route().Get)
	add(r, "route.list", "Route", "List routes in a project.", true, false, c.Route().List)
	add(r, "route.delete", "Route", "Delete a route.", false, true, c.Route().Delete)

	// WAF
	add(r, "waf.get", "WAF", "Get the WAF configuration for a zone.", true, false, c.WAF().Get)
	add(r, "waf.list", "WAF", "List WAF zones/rules for a project.", true, false, c.WAF().List)
	add(r, "waf.set", "WAF", "Set/replace the WAF configuration for a zone.", false, false, c.WAF().Set)
	add(r, "waf.delete", "WAF", "Delete a WAF zone configuration.", false, true, c.WAF().Delete)

	// Disk
	add(r, "disk.create", "Disk", "Create a persistent disk.", false, false, c.Disk().Create)
	add(r, "disk.get", "Disk", "Get a disk by name.", true, false, c.Disk().Get)
	add(r, "disk.list", "Disk", "List disks in a project.", true, false, c.Disk().List)
	add(r, "disk.update", "Disk", "Update a disk (e.g. resize).", false, false, c.Disk().Update)
	add(r, "disk.delete", "Disk", "Delete a disk.", false, true, c.Disk().Delete)
	add(r, "disk.metrics", "Disk", "Get usage metrics for a disk.", true, false, c.Disk().Metrics)

	// PullSecret
	add(r, "pullsecret.create", "PullSecret", "Create an image pull secret.", false, false, c.PullSecret().Create)
	add(r, "pullsecret.get", "PullSecret", "Get a pull secret by name.", true, false, c.PullSecret().Get)
	add(r, "pullsecret.list", "PullSecret", "List pull secrets in a project.", true, false, c.PullSecret().List)
	add(r, "pullsecret.delete", "PullSecret", "Delete a pull secret.", false, true, c.PullSecret().Delete)

	// WorkloadIdentity
	add(r, "workloadidentity.create", "WorkloadIdentity", "Create a workload identity.", false, false, c.WorkloadIdentity().Create)
	add(r, "workloadidentity.get", "WorkloadIdentity", "Get a workload identity by name.", true, false, c.WorkloadIdentity().Get)
	add(r, "workloadidentity.list", "WorkloadIdentity", "List workload identities in a project.", true, false, c.WorkloadIdentity().List)
	add(r, "workloadidentity.delete", "WorkloadIdentity", "Delete a workload identity.", false, true, c.WorkloadIdentity().Delete)

	// ServiceAccount
	add(r, "serviceaccount.create", "ServiceAccount", "Create a service account.", false, false, c.ServiceAccount().Create)
	add(r, "serviceaccount.get", "ServiceAccount", "Get a service account by name.", true, false, c.ServiceAccount().Get)
	add(r, "serviceaccount.list", "ServiceAccount", "List service accounts in a project.", true, false, c.ServiceAccount().List)
	add(r, "serviceaccount.update", "ServiceAccount", "Update a service account.", false, false, c.ServiceAccount().Update)
	add(r, "serviceaccount.delete", "ServiceAccount", "Delete a service account.", false, true, c.ServiceAccount().Delete)
	add(r, "serviceaccount.createKey", "ServiceAccount", "Create a key for a service account.", false, false, c.ServiceAccount().CreateKey)
	add(r, "serviceaccount.deleteKey", "ServiceAccount", "Delete a service account key.", false, true, c.ServiceAccount().DeleteKey)

	// Email
	add(r, "email.send", "Email", "Send an email through the project's email service.", false, false, c.Email().Send)
	add(r, "email.list", "Email", "List sent emails for a project.", true, false, c.Email().List)

	// Registry
	add(r, "registry.list", "Registry", "List container image repositories in a project.", true, false, c.Registry().List)
	add(r, "registry.get", "Registry", "Get a container image repository.", true, false, c.Registry().Get)
	add(r, "registry.getTags", "Registry", "List tags for a repository.", true, false, c.Registry().GetTags)
	add(r, "registry.getManifests", "Registry", "List manifests for a repository.", true, false, c.Registry().GetManifests)
	add(r, "registry.delete", "Registry", "Delete a repository, tag, or manifest.", false, true, c.Registry().Delete)

	// EnvGroup
	add(r, "envgroup.create", "EnvGroup", "Create an environment-variable group.", false, false, c.EnvGroup().Create)
	add(r, "envgroup.get", "EnvGroup", "Get an env group by name.", true, false, c.EnvGroup().Get)
	add(r, "envgroup.list", "EnvGroup", "List env groups in a project.", true, false, c.EnvGroup().List)
	add(r, "envgroup.update", "EnvGroup", "Update an env group.", false, false, c.EnvGroup().Update)
	add(r, "envgroup.delete", "EnvGroup", "Delete an env group.", false, true, c.EnvGroup().Delete)

	// AuditLog
	add(r, "auditlog.list", "AuditLog", "List audit log entries for a project.", true, false, c.AuditLog().List)

	// Dropbox
	add(r, "dropbox.list", "Dropbox", "List dropbox entries.", true, false, c.Dropbox().List)

	return r
}
