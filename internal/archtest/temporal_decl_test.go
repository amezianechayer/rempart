package archtest

import "testing"

// TestTemporalTypeDeclOutsideCmd proves obligation (bj) (threat T73): outside
// cmd/, no type declaration (alias or definition, at file level or local)
// whose right-hand side is a type of go.temporal.io/..., through a pointer,
// a slice, an array, a map, a channel or an embedded field, whatever the
// import name; under cmd/, and for a named field or a parameter, nothing is
// refused.
func TestTemporalTypeDeclOutsideCmd(t *testing.T) {
	const (
		workerImp = `"go.temporal.io/sdk/worker"`
		apiImp    = `commonpb "go.temporal.io/api/common/v1"`
		other     = "internal/other/t.go"
	)
	file := func(imp, body string) string { return goFile("other", []string{imp}, body) }
	runSourceCases(t, "no-temporal-type-decl", "", []srcCase{
		sc("alias", "", "client.Options", addFile(other, file(clientImp, "type O = client.Options\n"))),
		sc("definition", "", "client.Options", addFile(other, file(clientImp, "type O client.Options\n"))),
		sc("pointer", "", "client.Client", addFile(other, file(clientImp, "type O *client.Client\n"))),
		sc("slice", "", "worker.Options", addFile(other, file(workerImp, "type O []worker.Options\n"))),
		sc("array", "", "worker.Options", addFile(other, file(workerImp, "type O [2]worker.Options\n"))),
		sc("map_value", "", "client.Options", addFile(other, file(clientImp, "type O map[string]client.Options\n"))),
		sc("channel", "", "client.Options", addFile(other, file(clientImp, "type O chan client.Options\n"))),
		sc("parenthesized", "", "client.Options", addFile(other, file(clientImp, "type O = (client.Options)\n"))),
		sc("embedded", "", "client.Options", addFile(other, file(clientImp, "type O struct{ client.Options }\n"))),
		sc("embedded_pointer", "", "client.Options", addFile(other, file(clientImp, "type O struct {\n\tN int\n\t*client.Options\n}\n"))),
		sc("embedded_interface", "", "client.Client", addFile(other, file(clientImp, "type O interface{ client.Client }\n"))),
		sc("grouped", "", "client.Options", addFile(other, file(clientImp, "type (\n\tA int\n\tO = client.Options\n)\n"))),
		sc("local", "", "client.Options", addFile(other, file(clientImp, "func f() {\n\ttype O = client.Options\n\t_ = O{}\n}\n"))),
		sc("renamed_import", "", "client.Options", addFile(other, file("tc "+clientImp, "type O = tc.Options\n"))),
		sc("api_package", "", "v1.Payload", addFile(other, file(apiImp, "type P = commonpb.Payload\n"))),
		sc("in_loops", "", "client.Options", addFile("internal/loops/zz_t.go", goFile("loops", []string{clientImp}, "type o = client.Options\n"))),
	})
	t.Run("allowed", func(t *testing.T) {
		expectNoViolation(t,
			addFile("cmd/rempart-worker/zz_t.go", goFile("main", []string{clientImp}, "type opts = client.Options\n\ntype wrap struct{ client.Options }\n")),
			addFile(other, file(clientImp, "type H struct{ C client.Client }\n\nfunc f(o client.Options) { _ = o }\n")),
		)
	})
}
