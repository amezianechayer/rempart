package redact

// PositiveInputs gives the inputs of positiveCases to the external tests of
// this directory (property of plan M0-demo-prep, amendment V2).
func PositiveInputs() []string {
	ins := make([]string, len(positiveCases))
	for i, c := range positiveCases {
		ins[i] = c.in
	}
	return ins
}
