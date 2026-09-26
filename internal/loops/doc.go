// Package loops holds the generic loop workflow RunLoop, the approval wait
// AwaitApprovals and, later, one workflow per product loop. Neither knows a
// domain: payloads and candidates are opaque JSON, findings are normalized by
// package domain, approvals bind an opaque plan hash.
package loops
