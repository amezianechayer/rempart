// Package codec seals every Temporal payload of Rempart under the key of the
// tenant of the process (ADR 0001, ADR 0009, docs/plans/M1-codec-replay.md):
// data converter, failure converter and tenant propagator. No path yields or
// accepts a payload in clear.
package codec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
	"google.golang.org/protobuf/proto"

	"github.com/amezianechayer/rempart/internal/secrets/envelope"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

const (
	EncodingEnvelope      = "binary/rempart-envelope-v1"
	EncodingTenant        = "binary/rempart-tenant"
	TenantHeader          = "rempart-tenant"
	ErrTypeTenantMismatch = "TenantMismatch"             // non-retryable
	ErrTypeNotEncodable   = "RempartFailureNotEncodable" // D6, retryable
	SealedString          = "[sealed]"
)

var (
	ErrInvalid          = errors.New("codec: nil sealer or invalid tenant")
	ErrNoTenant         = errors.New("codec: no tenant in context")
	ErrPlaintextPayload = errors.New("codec: payload is not sealed")
	ErrNotCanonical     = errors.New("codec: payload is not canonical JSON")
	ErrNotRempart       = errors.New("codec: Temporal options without the Rempart converters")
)

// inner encodings admitted once a payload is opened (D3, D4): other inner
// encodings (protobuf) are refused, fail closed.
const (
	encodingNull   = "binary/null"
	encodingBinary = "binary/plain"
)

// dataConverter seals with the tenant of the process. A converter bound by
// WithContext or WithWorkflowContext carries bindErr when the context has no
// tenant or another tenant, and then refuses every call (D2).
type dataConverter struct {
	s       *envelope.Sealer
	tenant  tenancy.ID
	bindErr error
}

var (
	_ converter.DataConverter = (*dataConverter)(nil)
	_ workflow.ContextAware   = (*dataConverter)(nil)
)

// NewDataConverter returns the converter bound to the tenant of the process
// (ADR 0009); it implements workflow.ContextAware and never falls back to
// clear.
func NewDataConverter(s *envelope.Sealer, tenant tenancy.ID) (converter.DataConverter, error) {
	if s == nil {
		return nil, ErrInvalid
	}
	if _, err := tenancy.ParseID(string(tenant)); err != nil {
		return nil, ErrInvalid
	}
	return &dataConverter{s: s, tenant: tenant}, nil
}

func mismatch() error {
	return temporal.NewNonRetryableApplicationError("codec: tenant mismatch", ErrTypeTenantMismatch, nil)
}

// bound returns a copy of c checked against the tenant of a context.
func (c *dataConverter) bound(tenant tenancy.ID, ok bool) *dataConverter {
	b := &dataConverter{s: c.s, tenant: c.tenant}
	switch {
	case !ok:
		b.bindErr = ErrNoTenant
	case tenant != c.tenant:
		b.bindErr = mismatch()
	}
	return b
}

// WithContext binds c to the tenant of ctx (D2).
func (c *dataConverter) WithContext(ctx context.Context) converter.DataConverter {
	tenant, err := tenancy.FromContext(ctx)
	return c.bound(tenant, err == nil)
}

// WithWorkflowContext binds c to the tenant extracted by the propagator (D2).
func (c *dataConverter) WithWorkflowContext(ctx workflow.Context) converter.DataConverter {
	tenant, ok := workflowTenant(ctx)
	return c.bound(tenant, ok)
}

func (c *dataConverter) ctx() (context.Context, error) {
	if c.bindErr != nil {
		return nil, c.bindErr
	}
	ctx, err := tenancy.WithTenant(context.Background(), c.tenant)
	if err != nil {
		return nil, ErrInvalid
	}
	return ctx, nil
}

// ToPayload seals the inner payload of the SDK JSON converter (a RawValue is
// sealed as is): one metadata entry, encoding binary/rempart-envelope-v1 (D3).
func (c *dataConverter) ToPayload(value any) (*commonpb.Payload, error) {
	ctx, err := c.ctx()
	if err != nil {
		return nil, err
	}
	var inner *commonpb.Payload
	if raw, ok := value.(converter.RawValue); ok {
		inner = raw.Payload()
	} else if inner, err = converter.GetDefaultDataConverter().ToPayload(value); err != nil {
		return nil, fmt.Errorf("codec: encoding: %w", err)
	}
	plain, err := proto.Marshal(inner)
	if err != nil {
		return nil, errors.New("codec: encoding the inner payload")
	}
	sealed, err := c.s.Seal(ctx, plain)
	clear(plain)
	if err != nil {
		return nil, fmt.Errorf("codec: sealing: %w", err)
	}
	return &commonpb.Payload{
		Metadata: map[string][]byte{converter.MetadataEncoding: []byte(EncodingEnvelope)},
		Data:     sealed,
	}, nil
}

// open checks and opens a sealed payload into its inner payload: the tenant
// of the envelope header is checked before any unwrap.
func (c *dataConverter) open(p *commonpb.Payload) (*commonpb.Payload, error) {
	ctx, err := c.ctx()
	if err != nil {
		return nil, err
	}
	md := p.GetMetadata()
	if len(md) != 1 || !bytes.Equal(md[converter.MetadataEncoding], []byte(EncodingEnvelope)) {
		return nil, ErrPlaintextPayload
	}
	h, err := envelope.ParseHeader(p.GetData())
	if err != nil {
		return nil, fmt.Errorf("codec: opening: %w", err)
	}
	if h.Tenant != c.tenant {
		return nil, mismatch()
	}
	plain, err := c.s.Open(ctx, p.GetData())
	if err != nil {
		return nil, fmt.Errorf("codec: opening: %w", err)
	}
	inner := &commonpb.Payload{}
	err = proto.Unmarshal(plain, inner)
	clear(plain)
	if err != nil {
		return nil, fmt.Errorf("codec: opening: %w", envelope.ErrCorrupt)
	}
	return inner, nil
}

// FromPayload opens p and decodes the inner payload into valuePtr; a JSON
// payload must be canonical (D4): re-encoding the decoded value gives the
// same bytes.
func (c *dataConverter) FromPayload(p *commonpb.Payload, valuePtr any) error {
	inner, err := c.open(p)
	if err != nil {
		return err
	}
	if raw, ok := valuePtr.(*converter.RawValue); ok {
		*raw = converter.NewRawValue(inner)
		return nil
	}
	switch string(inner.GetMetadata()[converter.MetadataEncoding]) {
	case converter.MetadataEncodingJSON:
		if err := json.Unmarshal(inner.GetData(), valuePtr); err != nil {
			return fmt.Errorf("codec: decoding: %w", converter.ErrUnableToDecode)
		}
		again, err := json.Marshal(valuePtr)
		if err != nil || !bytes.Equal(again, inner.GetData()) {
			return ErrNotCanonical
		}
		return nil
	case encodingNull, encodingBinary:
		return converter.GetDefaultDataConverter().FromPayload(inner, valuePtr)
	default:
		return fmt.Errorf("codec: decoding: %w", converter.ErrEncodingIsNotSupported)
	}
}

func (c *dataConverter) ToPayloads(values ...any) (*commonpb.Payloads, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := &commonpb.Payloads{}
	for i, v := range values {
		p, err := c.ToPayload(v)
		if err != nil {
			return nil, fmt.Errorf("values[%d]: %w", i, err)
		}
		out.Payloads = append(out.Payloads, p)
	}
	return out, nil
}

func (c *dataConverter) FromPayloads(ps *commonpb.Payloads, valuePtrs ...any) error {
	for i, p := range ps.GetPayloads() {
		if i >= len(valuePtrs) {
			break
		}
		if err := c.FromPayload(p, valuePtrs[i]); err != nil {
			return fmt.Errorf("payload item %d: %w", i, err)
		}
	}
	return nil
}

// ToString never shows content.
func (c *dataConverter) ToString(*commonpb.Payload) string { return SealedString }

func (c *dataConverter) ToStrings(ps *commonpb.Payloads) []string {
	out := make([]string, len(ps.GetPayloads()))
	for i := range out {
		out[i] = SealedString
	}
	return out
}
