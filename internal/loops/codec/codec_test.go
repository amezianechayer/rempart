package codec_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	commonpb "go.temporal.io/api/common/v1"
	failurepb "go.temporal.io/api/failure/v1"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
	"google.golang.org/protobuf/proto"

	"github.com/amezianechayer/rempart/internal/loops"
	"github.com/amezianechayer/rempart/internal/loops/codec"
	"github.com/amezianechayer/rempart/internal/secrets/envelope"
	"github.com/amezianechayer/rempart/internal/secrets/fake"
	"github.com/amezianechayer/rempart/internal/secrets/ports"
	"github.com/amezianechayer/rempart/internal/secrets/secret"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// Tests of plan docs/plans/M1-codec-replay.md N3 to N7 (ADR 0001, ADR 0009).

const (
	tenantA tenancy.ID = "0d3e0000-0000-4000-8000-000000000001"
	tenantB tenancy.ID = "7b1c2d3e-4f50-4a6b-9c7d-8e9fa0b1c2d3"
	canary             = "CANARY-codec-5c1e9a"
)

var seed = [32]byte{0x52, 0x45, 0x4d, 0x50, 0x41, 0x52, 0x54, 0x2d, 0x54, 0x30, 0x32}

// value is a payload of the tests: canonical JSON by encoding/json.
type value struct {
	Secret string `json:"secret"`
	N      int    `json:"n"`
}

// spyKW counts the calls of a fake KeyWrapper at entry; down makes
// GenerateDataKey fail (Transit unavailable).
type spyKW struct {
	inner ports.KeyWrapper
	down  bool

	mu               sync.Mutex
	generate, unwrap int
}

var _ ports.KeyWrapper = (*spyKW)(nil)

func newSpy() *spyKW { return &spyKW{inner: fake.NewKeyWrapper(seed)} }

func (s *spyKW) GenerateDataKey(ctx context.Context, tenant tenancy.ID) (secret.Bytes, []byte, error) {
	s.mu.Lock()
	s.generate++
	s.mu.Unlock()
	if s.down {
		return secret.Bytes{}, nil, errors.New("key manager unavailable")
	}
	return s.inner.GenerateDataKey(ctx, tenant)
}

func (s *spyKW) UnwrapDataKey(ctx context.Context, tenant tenancy.ID, wrapped []byte) (secret.Bytes, error) {
	s.mu.Lock()
	s.unwrap++
	s.mu.Unlock()
	return s.inner.UnwrapDataKey(ctx, tenant, wrapped)
}

func (s *spyKW) calls() (generate, unwrap int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generate, s.unwrap
}

// newDC returns the data converter of Rempart for tenant over kw.
func newDC(t *testing.T, kw ports.KeyWrapper, tenant tenancy.ID) converter.DataConverter {
	t.Helper()
	s, err := envelope.NewSealer(kw, envelope.Options{})
	if err != nil {
		t.Fatalf("envelope.NewSealer: %v", err)
	}
	dc, err := codec.NewDataConverter(s, tenant)
	if err != nil {
		t.Fatalf("codec.NewDataConverter(%s): %v", tenant, err)
	}
	if dc == nil {
		t.Fatal("codec.NewDataConverter returned a nil converter without error")
	}
	return dc
}

// bind returns dc bound to ctx through workflow.ContextAware (D2).
func bind(t *testing.T, dc converter.DataConverter, ctx context.Context) converter.DataConverter {
	t.Helper()
	ca, ok := dc.(workflow.ContextAware)
	if !ok {
		t.Fatalf("%T does not implement workflow.ContextAware", dc)
	}
	b := ca.WithContext(ctx)
	if b == nil {
		t.Fatal("WithContext returned nil")
	}
	return b
}

func tenantCtx(t *testing.T, id tenancy.ID) context.Context {
	t.Helper()
	ctx, err := tenancy.WithTenant(context.Background(), id)
	if err != nil {
		t.Fatalf("tenancy.WithTenant(%s): %v", id, err)
	}
	return ctx
}

func wire(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	return b
}

// wantSealed checks the shape of a payload of Rempart: one metadata entry,
// encoding binary/rempart-envelope-v1, data an envelope of tenant.
func wantSealed(t *testing.T, p *commonpb.Payload, tenant tenancy.ID) {
	t.Helper()
	md := p.GetMetadata()
	if len(md) != 1 || string(md[converter.MetadataEncoding]) != codec.EncodingEnvelope {
		t.Fatalf("metadata %q, want exactly {encoding: %s}", md, codec.EncodingEnvelope)
	}
	h, err := envelope.ParseHeader(p.GetData())
	if err != nil {
		t.Fatalf("payload data is not an envelope: %v", err)
	}
	if h.Tenant != tenant {
		t.Errorf("envelope tenant %s, want %s", h.Tenant, tenant)
	}
}

func appError(t *testing.T, err error) *temporal.ApplicationError {
	t.Helper()
	var ae *temporal.ApplicationError
	if !errors.As(err, &ae) {
		t.Fatalf("error %v (%T) holds no ApplicationError", err, err)
	}
	return ae
}

// TestCodecRoundTrip (N3): bound to the context of tenant A, a value carrying a
// canary is sealed (one metadata entry, nothing in clear on the wire) and
// decodes back; RawValue yields the inner json/plain payload; ToString never
// shows content.
func TestCodecRoundTrip(t *testing.T) {
	kw := newSpy()
	dc := newDC(t, kw, tenantA)
	in := value{Secret: canary, N: 7}
	inner, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]converter.DataConverter{"bound": bind(t, dc, tenantCtx(t, tenantA)), "unbound": dc} {
		t.Run(name, func(t *testing.T) {
			p, err := c.ToPayload(in)
			if err != nil {
				t.Fatalf("ToPayload: %v", err)
			}
			wantSealed(t, p, tenantA)
			if b := wire(t, p); bytes.Contains(b, []byte(canary)) || bytes.Contains(b, []byte(converter.MetadataEncodingJSON)) {
				t.Error("the payload on the wire shows the canary or the inner encoding")
			}
			var out value
			if err := c.FromPayload(p, &out); err != nil || out != in {
				t.Errorf("FromPayload = %+v, %v; want %+v", out, err, in)
			}
			var raw converter.RawValue
			if err := c.FromPayload(p, &raw); err != nil {
				t.Fatalf("FromPayload(RawValue): %v", err)
			}
			rp := raw.Payload()
			if string(rp.GetMetadata()[converter.MetadataEncoding]) != converter.MetadataEncodingJSON || !bytes.Equal(rp.GetData(), inner) {
				t.Errorf("RawValue payload %q %q, want the inner json/plain payload %q", rp.GetMetadata(), rp.GetData(), inner)
			}
			// A RawValue is sealed as is, and opens to the same inner payload.
			again, err := c.ToPayload(raw)
			if err != nil {
				t.Fatalf("ToPayload(RawValue): %v", err)
			}
			wantSealed(t, again, tenantA)
			var raw2 converter.RawValue
			if err := c.FromPayload(again, &raw2); err != nil || !proto.Equal(raw2.Payload(), rp) {
				t.Errorf("RawValue round trip = %v, %v; want %v", raw2.Payload(), err, rp)
			}
			if s := c.ToString(p); s != codec.SealedString {
				t.Errorf("ToString = %q, want %q", s, codec.SealedString)
			}
			ps, err := c.ToPayloads(in, in)
			if err != nil {
				t.Fatalf("ToPayloads: %v", err)
			}
			for _, s := range c.ToStrings(ps) {
				if s != codec.SealedString {
					t.Errorf("ToStrings element %q, want %q", s, codec.SealedString)
				}
			}
		})
	}
	t.Run("constructor", func(t *testing.T) {
		s, err := envelope.NewSealer(kw, envelope.Options{})
		if err != nil {
			t.Fatal(err)
		}
		for name, mk := range map[string]func() (converter.DataConverter, error){
			"nil_sealer":     func() (converter.DataConverter, error) { return codec.NewDataConverter(nil, tenantA) },
			"invalid_tenant": func() (converter.DataConverter, error) { return codec.NewDataConverter(s, "not-a-tenant") },
			"empty_tenant":   func() (converter.DataConverter, error) { return codec.NewDataConverter(s, "") },
		} {
			if dc, err := mk(); !errors.Is(err, codec.ErrInvalid) || dc != nil {
				t.Errorf("%s: NewDataConverter = %v, %v; want nil, ErrInvalid", name, dc, err)
			}
		}
	})
}

// TestCodecNoTenantFails (N4, D2): bound to a context without tenant, the
// converter refuses to encode or decode, without calling the key manager.
func TestCodecNoTenantFails(t *testing.T) {
	kw := newSpy()
	dc := newDC(t, kw, tenantA)
	sealed, err := dc.ToPayload(value{Secret: canary})
	if err != nil {
		t.Fatalf("unbound ToPayload: %v", err)
	}
	g0, u0 := kw.calls()
	b := bind(t, dc, context.Background())
	p, err := b.ToPayload(value{Secret: canary})
	if !errors.Is(err, codec.ErrNoTenant) || p != nil {
		t.Errorf("ToPayload without tenant = %v, %v; want nil, ErrNoTenant", p, err)
	}
	if _, err := b.ToPayloads(value{Secret: canary}); err == nil {
		t.Error("ToPayloads without tenant succeeded")
	}
	var out value
	if err := b.FromPayload(sealed, &out); err == nil || out != (value{}) {
		t.Errorf("FromPayload without tenant = %+v, %v; want a refusal", out, err)
	}
	if g, u := kw.calls(); g != g0 || u != u0 {
		t.Errorf("key manager called without tenant: %d generations, %d unwraps; want none", g-g0, u-u0)
	}
}

// TestCodecRejectsPlaintextPayload (N5, T57): a json/plain or binary/null
// payload, or an envelope payload whose bytes were altered, is refused and
// never yields its value.
func TestCodecRejectsPlaintextPayload(t *testing.T) {
	kw := newSpy()
	dc := newDC(t, kw, tenantA)
	bound := bind(t, dc, tenantCtx(t, tenantA))
	plain, err := converter.GetDefaultDataConverter().ToPayload(value{Secret: canary, N: 1})
	if err != nil {
		t.Fatal(err)
	}
	null, err := converter.GetDefaultDataConverter().ToPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]*commonpb.Payload{"json_plain": plain, "binary_null": null} {
		for cname, c := range map[string]converter.DataConverter{"bound": bound, "unbound": dc} {
			t.Run(name+"/"+cname, func(t *testing.T) {
				var out value
				if err := c.FromPayload(p, &out); !errors.Is(err, codec.ErrPlaintextPayload) || out != (value{}) {
					t.Errorf("FromPayload = %+v, %v; want ErrPlaintextPayload and no value", out, err)
				}
				var raw converter.RawValue
				if err := c.FromPayload(p, &raw); !errors.Is(err, codec.ErrPlaintextPayload) || raw.Payload() != nil {
					t.Errorf("FromPayload(RawValue) = %v, %v; want ErrPlaintextPayload", raw.Payload(), err)
				}
			})
		}
	}
	t.Run("altered_envelope", func(t *testing.T) {
		sealed, err := bound.ToPayload(value{Secret: canary, N: 2})
		if err != nil {
			t.Fatal(err)
		}
		data := sealed.GetData()
		for _, i := range []int{0, 1, 60, len(data) / 2, len(data) - 1} {
			altered := proto.Clone(sealed).(*commonpb.Payload)
			altered.Data = bytes.Clone(data)
			altered.Data[i] ^= 0x01
			var out value
			if err := bound.FromPayload(altered, &out); err == nil || out != (value{}) {
				t.Errorf("byte %d altered: FromPayload = %+v, %v; want a refusal", i, out, err)
			}
		}
		truncated := proto.Clone(sealed).(*commonpb.Payload)
		truncated.Data = data[:len(data)-1]
		var out value
		if err := bound.FromPayload(truncated, &out); err == nil || out != (value{}) {
			t.Errorf("truncated: FromPayload = %+v, %v; want a refusal", out, err)
		}
	})
}

// TestCodecTenantMismatch (N6, T3, T18): a payload sealed by the converter of
// tenant B is refused by the converter of tenant A with a non-retryable
// TenantMismatch, before any unwrap; bound to the context of tenant B, the
// converter of A refuses to encode.
func TestCodecTenantMismatch(t *testing.T) {
	kw := newSpy()
	dcA, dcB := newDC(t, kw, tenantA), newDC(t, kw, tenantB)
	pB, err := bind(t, dcB, tenantCtx(t, tenantB)).ToPayload(value{Secret: canary})
	if err != nil {
		t.Fatalf("ToPayload for tenant B: %v", err)
	}
	wantSealed(t, pB, tenantB)
	wantMismatch := func(t *testing.T, err error) {
		t.Helper()
		ae := appError(t, err)
		if ae.Type() != codec.ErrTypeTenantMismatch || !ae.NonRetryable() {
			t.Errorf("error type %q non-retryable %v, want %q non-retryable", ae.Type(), ae.NonRetryable(), codec.ErrTypeTenantMismatch)
		}
		if strings.Contains(err.Error(), canary) {
			t.Errorf("error %q quotes the payload", err)
		}
	}
	for name, c := range map[string]converter.DataConverter{"unbound": dcA, "bound": bind(t, dcA, tenantCtx(t, tenantA))} {
		t.Run("open_"+name, func(t *testing.T) {
			_, u0 := kw.calls()
			var out value
			err := c.FromPayload(pB, &out)
			if err == nil || out != (value{}) {
				t.Fatalf("FromPayload = %+v, %v; want TenantMismatch", out, err)
			}
			wantMismatch(t, err)
			if _, u := kw.calls(); u != u0 {
				t.Errorf("%d UnwrapDataKey calls, want 0 (refused on the header)", u-u0)
			}
		})
	}
	t.Run("encode_for_other_tenant", func(t *testing.T) {
		g0, _ := kw.calls()
		p, err := bind(t, dcA, tenantCtx(t, tenantB)).ToPayload(value{Secret: canary})
		if err == nil || p != nil {
			t.Fatalf("ToPayload = %v, %v; want TenantMismatch", p, err)
		}
		wantMismatch(t, err)
		if g, _ := kw.calls(); g != g0 {
			t.Errorf("%d GenerateDataKey calls, want 0", g-g0)
		}
	})
}

// failureDetail carries the canary in an error detail.
type failureDetail struct {
	Note string `json:"note"`
}

// TestFailureMessageEncrypted (N7, T7, T11, ADR 0009): message, stack trace,
// cause and details of an ApplicationError are sealed on the wire and decode
// back; with the key manager down, the converter never panics and yields a
// fixed message without content.
func TestFailureMessageEncrypted(t *testing.T) {
	appErr := func() error {
		return temporal.NewApplicationErrorWithOptions("boom "+canary, "DemoFailure", temporal.ApplicationErrorOptions{
			Cause:   errors.New("cause " + canary),
			Details: []any{loops.ProposeFailure{Tokens: 3}, failureDetail{Note: canary}},
		})
	}
	t.Run("sealed", func(t *testing.T) {
		dc := newDC(t, newSpy(), tenantA)
		fc, err := codec.NewFailureConverter(dc)
		if err != nil {
			t.Fatalf("NewFailureConverter: %v", err)
		}
		f := fc.ErrorToFailure(appErr())
		if f == nil {
			t.Fatal("ErrorToFailure returned nil")
		}
		if b := wire(t, f); bytes.Contains(b, []byte(canary)) || bytes.Contains(b, []byte(`"tokens"`)) {
			t.Error("the failure on the wire shows the canary or a detail in clear")
		}
		if f.GetMessage() != "Encoded failure" || f.GetStackTrace() != "" {
			t.Errorf("message %q, stack %q; want the SDK placeholder and no stack", f.GetMessage(), f.GetStackTrace())
		}
		wantSealed(t, f.GetEncodedAttributes(), tenantA)
		for _, p := range f.GetApplicationFailureInfo().GetDetails().GetPayloads() {
			wantSealed(t, p, tenantA)
		}
		back := fc.FailureToError(f)
		ae := appError(t, back)
		if ae.Type() != "DemoFailure" || !strings.Contains(ae.Error(), "boom "+canary) {
			t.Errorf("decoded error %q of type %q, want the message and type back", ae.Error(), ae.Type())
		}
		if c := errors.Unwrap(ae); c == nil || !strings.Contains(c.Error(), "cause "+canary) {
			t.Errorf("decoded cause %v, want the cause message back", c)
		}
		var pf loops.ProposeFailure
		var fd failureDetail
		if err := ae.Details(&pf, &fd); err != nil || pf.Tokens != 3 || fd.Note != canary {
			t.Errorf("details %+v %+v, %v; want {3} and the canary", pf, fd, err)
		}
	})
	t.Run("keywrapper_down", func(t *testing.T) {
		kw := newSpy()
		kw.down = true
		fc, err := codec.NewFailureConverter(newDC(t, kw, tenantA))
		if err != nil {
			t.Fatalf("NewFailureConverter: %v", err)
		}
		var f *failurepb.Failure
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ErrorToFailure panicked: %v", r)
				}
			}()
			f = fc.ErrorToFailure(appErr())
		}()
		if f == nil {
			t.Fatal("ErrorToFailure returned nil")
		}
		if bytes.Contains(wire(t, f), []byte(canary)) {
			t.Error("the fallback failure shows the canary")
		}
		info := f.GetApplicationFailureInfo()
		if f.GetMessage() != "rempart: failure not encodable" || info.GetType() != codec.ErrTypeNotEncodable || info.GetNonRetryable() {
			t.Errorf("message %q, type %q, non-retryable %v; want the fixed message, %q, retryable",
				f.GetMessage(), info.GetType(), info.GetNonRetryable(), codec.ErrTypeNotEncodable)
		}
		if f.GetStackTrace() != "" || info.GetDetails() != nil || f.GetEncodedAttributes() != nil || f.GetCause() != nil {
			t.Errorf("fallback failure carries a stack, details, attributes or a cause: %v", f)
		}
	})
	t.Run("foreign_data_converter", func(t *testing.T) {
		if fc, err := codec.NewFailureConverter(converter.GetDefaultDataConverter()); !errors.Is(err, codec.ErrNotRempart) || fc != nil {
			t.Errorf("NewFailureConverter(default) = %v, %v; want nil, ErrNotRempart", fc, err)
		}
	})
}

// Compile-time guard of the exported surface named by the plan.
var (
	_ = fmt.Sprint(codec.EncodingTenant, codec.TenantHeader)
	_ = codec.Check
	_ = codec.NewTenantPropagator
)
