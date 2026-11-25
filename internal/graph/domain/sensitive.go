package domain

// SensitiveData reports whether n holds sensitive data (closing review of M2,
// T139): a data store whose classification is absent (read on the safe side)
// or other than public and internal, or which carries any regulation,
// whatever its classification. The one definition of the core invariant of
// L2, the confirmation summary and STRIDE; the design pack holds the same in
// lib.sensitive_data, and L1 in its exposure rule.
func (n FactNode) SensitiveData() bool {
	if n.Kind != KindDataStore {
		return false
	}
	c := n.Attrs.Classification
	return c == nil || (*c != "public" && *c != "internal") || len(n.Attrs.Regulation) > 0
}
