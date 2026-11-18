package loops_test

import (
	"testing"

	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/workflow"

	"github.com/amezianechayer/rempart/internal/loops/codec"
	"github.com/amezianechayer/rempart/internal/secrets/envelope"
	secretsfake "github.com/amezianechayer/rempart/internal/secrets/fake"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// Reference histories (D10 of M1-codec-replay, ADR 0001 "chiffrés avec la clé
// du faux"): recorded and replayed with the in-process key wrapper of this
// fixed seed, for this tenant.
var replaySeed = [32]byte{0x52, 0x45, 0x50, 0x4c, 0x41, 0x59}

const replayTenant = tenancy.ID("0f8fad5b-d9cb-469f-a165-70867728950e")

// replayConverters are the converters of Rempart on the replay key.
func replayConverters(t *testing.T) (converter.DataConverter, converter.FailureConverter, []workflow.ContextPropagator) {
	t.Helper()
	s, err := envelope.NewSealer(secretsfake.NewKeyWrapper(replaySeed), envelope.Options{})
	if err != nil {
		t.Fatal(err)
	}
	dc, err := codec.NewDataConverter(s, replayTenant)
	if err != nil {
		t.Fatal(err)
	}
	fc, err := codec.NewFailureConverter(dc)
	if err != nil {
		t.Fatal(err)
	}
	return dc, fc, []workflow.ContextPropagator{codec.NewTenantPropagator()}
}
