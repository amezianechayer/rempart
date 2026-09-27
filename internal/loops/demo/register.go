package demo

import (
	"context"
	"errors"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/workflow"

	"github.com/amezianechayer/rempart/internal/loops"
	"github.com/amezianechayer/rempart/internal/loops/demo/activities"
)

var ErrInvalidRegistration = errors.New("demo: nil registry, activities or approval verifier")

// Registry is satisfied by worker.Worker and the test suite environment.
type Registry interface {
	RegisterWorkflowWithOptions(w any, options workflow.RegisterOptions)
	RegisterActivityWithOptions(a any, options activity.RegisterOptions)
}

// ApprovalVerifier checks one approval signature; T20 wires one that refuses all.
type ApprovalVerifier interface {
	VerifyApproval(ctx context.Context, a loops.Approval) (loops.ApprovalCheck, error)
}

func Register(r Registry, a *activities.Activities, v ApprovalVerifier) error {
	if r == nil || a == nil || v == nil {
		return ErrInvalidRegistration
	}
	r.RegisterWorkflowWithOptions(Workflow, workflow.RegisterOptions{Name: WorkflowName})
	r.RegisterActivityWithOptions(a.Propose, activity.RegisterOptions{Name: ProposeActivity})
	r.RegisterActivityWithOptions(a.Verify, activity.RegisterOptions{Name: VerifyActivity})
	r.RegisterActivityWithOptions(a.Commit, activity.RegisterOptions{Name: CommitActivity})
	r.RegisterActivityWithOptions(v.VerifyApproval, activity.RegisterOptions{Name: VerifyApprovalActivity})
	return nil
}
