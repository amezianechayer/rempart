package l1

import (
	"errors"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/workflow"

	"github.com/amezianechayer/rempart/internal/loops/l1/activities"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

var ErrInvalidRegistration = errors.New("l1: nil registry or activities, or not a customer tenant")

// Registry is satisfied by worker.Worker and the test suite environment.
type Registry interface {
	RegisterWorkflowWithOptions(w any, options workflow.RegisterOptions)
	RegisterActivityWithOptions(a any, options activity.RegisterOptions)
}

// Register registers L1 for the tenant of a (T34, T75). The caller checks the
// converters of Rempart first (codec.Check, §4.1 of the threat model).
func Register(r Registry, a *activities.Activities) error {
	if r == nil || a == nil || a.LLM == nil {
		return ErrInvalidRegistration
	}
	if id, err := tenancy.ParseID(string(a.Tenant)); err != nil || id == tenancy.System {
		return ErrInvalidRegistration
	}
	r.RegisterWorkflowWithOptions(Workflow, workflow.RegisterOptions{Name: WorkflowName})
	r.RegisterActivityWithOptions(a.Prepare, activity.RegisterOptions{Name: PrepareActivity})
	r.RegisterActivityWithOptions(a.Propose, activity.RegisterOptions{Name: ProposeActivity})
	r.RegisterActivityWithOptions(a.Verify, activity.RegisterOptions{Name: VerifyActivity})
	r.RegisterActivityWithOptions(a.Finalize, activity.RegisterOptions{Name: FinalizeActivity})
	return nil
}
