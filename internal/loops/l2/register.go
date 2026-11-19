package l2

import (
	"errors"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/workflow"

	"github.com/amezianechayer/rempart/internal/loops/l2/activities"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

var ErrInvalidRegistration = errors.New("l2: nil registry, activities or policy pack, or not a customer tenant")

// Registry is satisfied by worker.Worker and the test suite environment.
type Registry interface {
	RegisterWorkflowWithOptions(w any, options workflow.RegisterOptions)
	RegisterActivityWithOptions(a any, options activity.RegisterOptions)
}

// Register registers L2 for the tenant of a, with its compiled pack (T3, T34,
// T75). The caller checks the converters of Rempart first (codec.Check).
func Register(r Registry, a *activities.Activities) error {
	if r == nil || a == nil || a.Policy == nil {
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
