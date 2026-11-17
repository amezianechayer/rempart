package archtest

import "testing"

// TestTemporalDialConfined (obligation (dl), before M1-T05): a Temporal client
// or worker is created only by cmd/rempart-worker, whose registrations check
// the Rempart converters (codec.Check): no other command or package can run a
// worker over a client whose history would be written in clear (§4.1).
func TestTemporalDialConfined(t *testing.T) {
	const imp = "import (\n\t\"context\"\n\n\t\"go.temporal.io/sdk/client\"\n\t\"go.temporal.io/sdk/worker\"\n)\n\n"
	runSourceCases(t, "temporal-dial-confined", "", []srcCase{
		sc("dial_context_in_evals", "", "DialContext", addFile("cmd/rempart-evals/zz_dial.go",
			"package main\n\n"+imp+"func dial(ctx context.Context) (client.Client, error) { return client.DialContext(ctx, client.Options{}) }\n\n"+
				"var _ = worker.Options{}\n")),
		sc("worker_new_in_cli", "", "worker.New", addFile("cmd/rempart/zz_worker.go",
			"package main\n\n"+imp+"func run(c client.Client) { _ = worker.New(c, \"q\", worker.Options{}) }\n\nvar _ = context.Background\n")),
		sc("dial_as_value", "", "Dial", addFile("cmd/rempart/zz_value.go",
			"package main\n\n"+imp+"var dial = client.Dial\n\nvar (\n\t_ = context.Background\n\t_ = worker.Options{}\n)\n")),
		sc("lazy_client", "", "NewLazyClient", addFile("cmd/rempart/zz_lazy.go",
			"package main\n\n"+imp+"func lazy() { _, _ = client.NewLazyClient(client.Options{}) }\n\nvar (\n\t_ = context.Background\n\t_ = worker.Options{}\n)\n")),
	})
}
