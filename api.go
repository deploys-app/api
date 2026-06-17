package api

type Interface interface {
	Me() Me
	Billing() Billing
	Location() Location
	Project() Project
	Role() Role
	Deployment() Deployment
	Domain() Domain
	Route() Route
	WAF() WAF
	Cache() Cache
	Disk() Disk
	PullSecret() PullSecret
	WorkloadIdentity() WorkloadIdentity
	ServiceAccount() ServiceAccount
	Email() Email
	Registry() Registry
	EnvGroup() EnvGroup
	Collector() Collector
	Deployer() Deployer
	Access() Access
	AuditLog() AuditLog
	Dropbox() Dropbox
	GitHub() GitHub
	Scheduler() Scheduler
}
