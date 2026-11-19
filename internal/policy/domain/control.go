// Package domain holds the pure types of the policy engine: controls and their
// closed remediation vocabulary, the jurisdiction table and the facts derived
// in Go for the policies (ADR 0011). No free text, no dependency.
package domain

import (
	"slices"

	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
)

// Remediation is the closed vocabulary read in custom.remediation of every
// rule (D5 of docs/plans/M2-overview.md): what the reviser of L2 may apply.
type Remediation string

// Remediations of the vocabulary.
const (
	RemediationMakePrivate             Remediation = "make_private"
	RemediationRemoveExposure          Remediation = "remove_exposure"
	RemediationHTTPSOnly               Remediation = "https_only"
	RemediationEncryptTransit          Remediation = "encrypt_transit"
	RemediationMoveToDataTier          Remediation = "move_to_data_tier"
	RemediationEnableEncryption        Remediation = "enable_encryption"
	RemediationLeastPrivilege          Remediation = "least_privilege"
	RemediationDedicatedIdentity       Remediation = "dedicated_identity"
	RemediationUseWorkloadIdentity     Remediation = "use_workload_identity"
	RemediationEnableAuditLog          Remediation = "enable_audit_log"
	RemediationEnableSecretsEncryption Remediation = "enable_secrets_encryption"
	RemediationEnableAdmission         Remediation = "enable_admission"
	RemediationDefaultDenyNetpol       Remediation = "default_deny_netpol"
	RemediationEscalate                Remediation = "escalate"
	RemediationAdvisory                Remediation = "advisory"
)

var remediations = []Remediation{
	RemediationMakePrivate, RemediationRemoveExposure, RemediationHTTPSOnly, RemediationEncryptTransit,
	RemediationMoveToDataTier, RemediationEnableEncryption, RemediationLeastPrivilege, RemediationDedicatedIdentity,
	RemediationUseWorkloadIdentity, RemediationEnableAuditLog, RemediationEnableSecretsEncryption,
	RemediationEnableAdmission, RemediationDefaultDenyNetpol, RemediationEscalate, RemediationAdvisory,
}

// Remediations returns the vocabulary.
func Remediations() []Remediation { return slices.Clone(remediations) }

// Control is one control of a pack, read from its verified metadata.
type Control struct {
	ID          string
	Title       string
	Severity    loopsdomain.Severity
	Remediation Remediation
}
