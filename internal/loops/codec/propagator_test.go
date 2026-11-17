package codec_test

import (
	"context"
	"errors"
	"testing"

	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"

	"github.com/amezianechayer/rempart/internal/loops/codec"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// Obligation (dk), before M1-T05: the tenant boundary of the rempart-tenant
// header.

type headers map[string]*commonpb.Payload

func (h headers) Set(k string, p *commonpb.Payload) { h[k] = p }

func (h headers) Get(k string) (*commonpb.Payload, bool) {
	p, ok := h[k]
	return p, ok
}

func (h headers) ForEachKey(f func(string, *commonpb.Payload) error) error {
	for k, p := range h {
		if err := f(k, p); err != nil {
			return err
		}
	}
	return nil
}

func tenantHeader(data string) headers {
	return headers{codec.TenantHeader: {
		Metadata: map[string][]byte{converter.MetadataEncoding: []byte(codec.EncodingTenant)},
		Data:     []byte(data),
	}}
}

// TestPropagatorTenantBoundary: inject writes exactly the tenant; extract
// refuses a malformed header, leaves a context without header tenantless,
// and a converter bound to another tenant refuses to encode.
func TestPropagatorTenantBoundary(t *testing.T) {
	p := codec.NewTenantPropagator()
	if err := p.Inject(context.Background(), headers{}); err == nil {
		t.Error("Inject without tenant succeeded")
	}
	h := headers{}
	if err := p.Inject(tenantCtx(t, tenantA), h); err != nil {
		t.Fatalf("Inject: %v", err)
	}
	if len(h) != 1 || string(h[codec.TenantHeader].GetData()) != string(tenantA) ||
		string(h[codec.TenantHeader].GetMetadata()[converter.MetadataEncoding]) != codec.EncodingTenant {
		t.Errorf("headers %v, want exactly %s=%s", h, codec.TenantHeader, tenantA)
	}

	ctx, err := p.Extract(context.Background(), headers{})
	if err != nil {
		t.Fatalf("Extract without header: %v", err)
	}
	if _, err := tenancy.FromContext(ctx); err == nil {
		t.Error("a context without header carries a tenant")
	}
	dc := newDC(t, newSpy(), tenantA)
	if _, err := bind(t, dc, ctx).ToPayload(value{Text: canary}); !errors.Is(err, codec.ErrNoTenant) {
		t.Errorf("converter bound to a context without header: %v, want ErrNoTenant", err)
	}

	for name, bad := range map[string]headers{
		"not_a_uuid":   tenantHeader("not-a-tenant"),
		"empty":        tenantHeader(""),
		"json_plain":   {codec.TenantHeader: {Metadata: map[string][]byte{converter.MetadataEncoding: []byte(converter.MetadataEncodingJSON)}, Data: []byte(`"` + string(tenantA) + `"`)}},
		"no_metadata":  {codec.TenantHeader: {Data: []byte(tenantA)}},
		"two_metadata": {codec.TenantHeader: {Metadata: map[string][]byte{converter.MetadataEncoding: []byte(codec.EncodingTenant), "x": nil}, Data: []byte(tenantA)}},
	} {
		if _, err := p.Extract(context.Background(), bad); err == nil {
			t.Errorf("%s: Extract accepted a malformed header", name)
		}
	}

	ctxB, err := p.Extract(context.Background(), tenantHeader(string(tenantB)))
	if err != nil {
		t.Fatalf("Extract tenant B: %v", err)
	}
	pl, err := bind(t, dc, ctxB).ToPayload(value{Text: canary})
	if err == nil || pl != nil {
		t.Fatalf("converter of A bound to tenant B encoded: %v", err)
	}
	if ae := appError(t, err); ae.Type() != codec.ErrTypeTenantMismatch || !ae.NonRetryable() {
		t.Errorf("error type %q, want non-retryable %s", ae.Type(), codec.ErrTypeTenantMismatch)
	}
}
