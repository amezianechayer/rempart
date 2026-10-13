package codec

import (
	"bytes"
	"context"
	"errors"

	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/workflow"

	"github.com/amezianechayer/rempart/internal/tenancy"
)

var errHeader = errors.New("codec: malformed rempart-tenant header")

// tenantKey is the key of the tenant in a workflow context.
type tenantKey struct{}

// tenantPropagator carries the tenant in one header, rempart-tenant, whose
// data are the 36 bytes of the UUID (D5); every other header key is ignored.
type tenantPropagator struct{}

// NewTenantPropagator returns the propagator of Rempart.
func NewTenantPropagator() workflow.ContextPropagator { return &tenantPropagator{} }

func workflowTenant(ctx workflow.Context) (tenancy.ID, bool) {
	if ctx == nil {
		return "", false
	}
	id, ok := ctx.Value(tenantKey{}).(tenancy.ID)
	return id, ok && id != ""
}

func header(id tenancy.ID) *commonpb.Payload {
	return &commonpb.Payload{
		Metadata: map[string][]byte{converter.MetadataEncoding: []byte(EncodingTenant)},
		Data:     []byte(id),
	}
}

// read returns the tenant of the header, ok false if the header is absent.
func read(hr workflow.HeaderReader) (tenancy.ID, bool, error) {
	p, ok := hr.Get(TenantHeader)
	if !ok {
		return "", false, nil
	}
	md := p.GetMetadata()
	if len(md) != 1 || !bytes.Equal(md[converter.MetadataEncoding], []byte(EncodingTenant)) {
		return "", false, errHeader
	}
	id, err := tenancy.ParseID(string(p.GetData()))
	if err != nil {
		return "", false, errHeader
	}
	return id, true, nil
}

func (*tenantPropagator) Inject(ctx context.Context, hw workflow.HeaderWriter) error {
	id, err := tenancy.FromContext(ctx)
	if err != nil {
		return ErrNoTenant
	}
	hw.Set(TenantHeader, header(id))
	return nil
}

func (*tenantPropagator) Extract(ctx context.Context, hr workflow.HeaderReader) (context.Context, error) {
	id, ok, err := read(hr)
	if err != nil || !ok {
		return ctx, err
	}
	return tenancy.WithTenant(ctx, id)
}

func (*tenantPropagator) InjectFromWorkflow(ctx workflow.Context, hw workflow.HeaderWriter) error {
	id, ok := workflowTenant(ctx)
	if !ok {
		return ErrNoTenant
	}
	hw.Set(TenantHeader, header(id))
	return nil
}

func (*tenantPropagator) ExtractToWorkflow(ctx workflow.Context, hr workflow.HeaderReader) (workflow.Context, error) {
	id, ok, err := read(hr)
	if err != nil || !ok {
		return ctx, err
	}
	return workflow.WithValue(ctx, tenantKey{}, id), nil
}
