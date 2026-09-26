package fake_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/amezianechayer/rempart/internal/loops"
	"github.com/amezianechayer/rempart/internal/loops/fake"
)

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func sign(approver string) loops.Approval {
	a := loops.Approval{Approved: true, PlanHash: strings.Repeat("ab", 32), Approver: approver}
	a.Signature = fake.ExpectedSignature(a)
	return a
}

func TestFakeExpectedSignature(t *testing.T) {
	h := strings.Repeat("ab", 32)
	a := loops.Approval{Approved: true, PlanHash: h, Approver: "bob", Signature: "not covered"}
	if got := fake.ExpectedSignature(a); got != sum("4:fake,3:bob,64:"+h+",4:true,") {
		t.Errorf("approval: %s", got)
	}
	a.Approved = false
	if got := fake.ExpectedSignature(a); got != sum("4:fake,3:bob,64:"+h+",5:false,") {
		t.Errorf("refusal: %s", got)
	}
	if fake.ExpectedSignature(loops.Approval{Approver: "a|b", PlanHash: "c"}) == fake.ExpectedSignature(loops.Approval{Approver: "a", PlanHash: "b|c"}) {
		t.Error("ambiguous encoding")
	}
}

func TestFakeApprovalVerifier(t *testing.T) {
	v := &fake.ApprovalVerifier{SecurityRoles: map[string]bool{"carol": true, "mallory": true}}
	stolen, upper, empty := sign("mallory"), sign("carol"), sign("carol")
	stolen.Signature, upper.Signature, empty.Signature = sign("bob").Signature, strings.ToUpper(upper.Signature), ""
	for i, c := range []struct {
		a    loops.Approval
		want loops.ApprovalCheck
	}{
		{sign("bob"), loops.ApprovalCheck{SignatureValid: true}},
		{sign("carol"), loops.ApprovalCheck{SignatureValid: true, SecurityRole: true}},
		{stolen, loops.ApprovalCheck{}},
		{upper, loops.ApprovalCheck{}},
		{empty, loops.ApprovalCheck{}},
	} {
		if got, err := v.VerifyApproval(t.Context(), c.a); err != nil || got != c.want {
			t.Errorf("case %d: %+v, %v; want %+v", i, got, err, c.want)
		}
	}
	if got, err := (&fake.ApprovalVerifier{}).VerifyApproval(t.Context(), sign("carol")); err != nil || got != (loops.ApprovalCheck{SignatureValid: true}) {
		t.Errorf("without roles: %+v, %v", got, err)
	}
}
