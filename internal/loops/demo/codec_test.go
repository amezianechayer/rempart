package demo_test

import (
	"encoding/json"
	"testing"
	"time"

	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/workflow"

	llmfake "github.com/amezianechayer/rempart/internal/llm/fake"
	"github.com/amezianechayer/rempart/internal/loops"
	"github.com/amezianechayer/rempart/internal/loops/codec"
	"github.com/amezianechayer/rempart/internal/secrets/envelope"
	secretsfake "github.com/amezianechayer/rempart/internal/secrets/fake"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// M1-T02 (lean mode): the demo runs through the codec of Rempart, as the
// worker wires it: data converter, failure converter, tenant propagator and
// the rempart-tenant header set by the client.

// sealed puts the converters of Rempart for tenant on the environment of h.
func sealed(t *testing.T, h *harness, tenant tenancy.ID) *harness {
	t.Helper()
	s, err := envelope.NewSealer(secretsfake.NewKeyWrapper([32]byte{0x44, 0x45, 0x4d, 0x4f}), envelope.Options{})
	if err != nil {
		t.Fatal(err)
	}
	dc, err := codec.NewDataConverter(s, tenant)
	if err != nil {
		t.Fatal(err)
	}
	fc, err := codec.NewFailureConverter(dc)
	if err != nil {
		t.Fatal(err)
	}
	h.env.SetDataConverter(dc)
	h.env.SetFailureConverter(fc)
	h.env.SetContextPropagators([]workflow.ContextPropagator{codec.NewTenantPropagator()})
	h.env.SetHeader(&commonpb.Header{Fields: map[string]*commonpb.Payload{codec.TenantHeader: {
		Metadata: map[string][]byte{converter.MetadataEncoding: []byte(codec.EncodingTenant)},
		Data:     []byte(tenant),
	}}})
	return h
}

// TestDemoThroughCodec: input, activities, signals and output go through the
// codec; the loop converges, a valid signed approval commits once.
func TestDemoThroughCodec(t *testing.T) {
	t.Run("timed_out", func(t *testing.T) {
		h := sealed(t, newHarness(t, tenantA, []llmfake.Step{answer(greetBonjour)}), tenantA)
		out := mustRun(t, h, input())
		if out.Loop.Status != loops.StatusConverged || out.Approval.Outcome != loops.OutcomeTimedOut || out.Committed {
			t.Errorf("loop %s, approval %s, committed %v; want converged, timed_out, false", out.Loop.Status, out.Approval.Outcome, out.Committed)
		}
	})
	t.Run("approved", func(t *testing.T) {
		h := sealed(t, newHarness(t, tenantA, []llmfake.Step{answer(greetBonjour)}), tenantA)
		h.signalAt(time.Second, signedBy("bob", expectedHash(greetBonjour)))
		out := mustRun(t, h, input())
		if out.Approval.Outcome != loops.OutcomeApproved || !out.Committed || h.count(commitName) != 1 {
			t.Errorf("approval %s, committed %v, %d commits; want approved, true, 1", out.Approval.Outcome, out.Committed, h.count(commitName))
		}
	})
}

// TestStrictInputDecoding (obligation (ax), D4, T57; replaces
// TestDemoInputDecodingFrozen): through the codec, an input that is not the
// canonical encoding of demo.Input fails the workflow before any provider
// call; the canonical input converges.
func TestStrictInputDecoding(t *testing.T) {
	const rest = `"author":"alice","approval_timeout":5000000000`
	cases := []struct{ name, raw string }{
		{"extra_tenant", `{"target":"bonjour",` + rest + `,"tenant":"` + string(tenantB) + `"}`},
		{"upper_case_key", `{"TARGET":"bonjour",` + rest + `}`},
		{"duplicate_key", `{"target":"salut","target":"bonjour",` + rest + `}`},
		{"reordered_keys", `{"author":"alice","target":"bonjour","approval_timeout":5000000000}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := sealed(t, newHarness(t, tenantA, []llmfake.Step{answer(greetBonjour)}), tenantA)
			if _, err := h.run(t, json.RawMessage(tc.raw)); err == nil {
				t.Fatal("workflow succeeded, want a decoding failure")
			}
			if n := len(h.prov.Calls()); n != 0 || h.total() != 0 {
				t.Errorf("%d provider calls, %d activities; want 0, 0", n, h.total())
			}
		})
	}
	t.Run("canonical_control", func(t *testing.T) {
		h := sealed(t, newHarness(t, tenantA, []llmfake.Step{answer(greetBonjour)}), tenantA)
		out := mustRun(t, h, json.RawMessage(`{"target":"bonjour",`+rest+`}`))
		if out.Loop.Status != loops.StatusConverged {
			t.Errorf("loop %s, want converged", out.Loop.Status)
		}
	})
}
