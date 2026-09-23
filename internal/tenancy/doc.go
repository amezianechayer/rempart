// Package tenancy handles tenant isolation, RBAC and identities.
//
// M0 (docs/plans/M0-tenancy.md, ADR 0004): the tenant identifier ID, the
// reserved System tenant, and the tenant carried by context.Context, checked
// at every boundary with Require. RBAC and identities come in later milestones.
package tenancy
