// Package fake holds deterministic fakes of the loop engine: tests and the
// -dev composition root only (rule R5). Its approval verifier has no key:
// anyone can compute a valid signature (threats T12, T41).
package fake

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strconv"

	"github.com/amezianechayer/rempart/internal/loops"
)

// ApprovalVerifier accepts a signature if and only if it equals
// ExpectedSignature; SecurityRoles lists the approvers with the security role.
type ApprovalVerifier struct{ SecurityRoles map[string]bool }

// ExpectedSignature returns the hex SHA-256 of the netstrings of "fake", the
// approver, the plan hash and the decision ("true" or "false").
func ExpectedSignature(a loops.Approval) string {
	var buf []byte
	for _, s := range []string{"fake", a.Approver, a.PlanHash, strconv.FormatBool(a.Approved)} {
		buf = strconv.AppendInt(buf, int64(len(s)), 10)
		buf = append(buf, ':')
		buf = append(buf, s...)
		buf = append(buf, ',')
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

// VerifyApproval is the verification activity; it never fails. The role
// counts only with a valid signature.
func (v *ApprovalVerifier) VerifyApproval(_ context.Context, a loops.Approval) (loops.ApprovalCheck, error) {
	ok := subtle.ConstantTimeCompare([]byte(a.Signature), []byte(ExpectedSignature(a))) == 1
	return loops.ApprovalCheck{SignatureValid: ok, SecurityRole: ok && v.SecurityRoles[a.Approver]}, nil
}
