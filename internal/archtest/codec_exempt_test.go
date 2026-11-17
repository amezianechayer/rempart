package archtest

import "testing"

// TestCodecExemptionExact (obligation (do), M1-T02 D11): only the package
// internal/loops/codec is out of the workflow and decoding classes, not its
// subpackages; the codec never uses the Temporal client nor the worker.
func TestCodecExemptionExact(t *testing.T) {
	runSourceCases(t, "", "", []srcCase{
		sc("codec_subpackage_decodes", "loops-no-json-decoding", "Unmarshal", addFile("internal/loops/codec/zz/zz.go",
			"package zz\n\nimport (\n\t\"encoding/json\"\n\n\t\"go.temporal.io/sdk/workflow\"\n)\n\n"+
				"func decode(_ workflow.Context, b []byte) {\n\tvar v any\n\t_ = json.Unmarshal(b, &v)\n}\n")),
		sc("codec_uses_client", "loops-codec-confined", "client.Options", addFile("internal/loops/codec/zz_client.go",
			"package codec\n\nimport \"go.temporal.io/sdk/client\"\n\nvar _ client.Options\n")),
		sc("codec_uses_worker", "loops-codec-confined", "worker.Options", addFile("internal/loops/codec/zz_worker.go",
			"package codec\n\nimport \"go.temporal.io/sdk/worker\"\n\nvar _ worker.Options\n")),
	})
}
