package codec

import (
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/workflow"
)

// Check accepts only the converters of Rempart: dc from NewDataConverter, fc
// built on that dc, ps exactly the propagator of Rempart; ErrNotRempart
// otherwise.
func Check(dc converter.DataConverter, fc converter.FailureConverter, ps []workflow.ContextPropagator) error {
	c, ok := dc.(*dataConverter)
	if !ok || c == nil || c.bindErr != nil {
		return ErrNotRempart
	}
	f, ok := fc.(*failureConverter)
	if !ok || f == nil || f.dc != c {
		return ErrNotRempart
	}
	if len(ps) != 1 {
		return ErrNotRempart
	}
	if p, ok := ps[0].(*tenantPropagator); !ok || p == nil {
		return ErrNotRempart
	}
	return nil
}
