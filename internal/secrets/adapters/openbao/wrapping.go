package openbao

import (
	"context"
	"errors"
	"fmt"

	"github.com/amezianechayer/rempart/internal/secrets/secret"
)

// WorkerPolicy is the only policy a worker token may carry (plan
// M1-codec-replay D9, option O5).
const WorkerPolicy = "rempart-worker"

// maxWorkerLease bounds the lifetime of an unwrapped worker token (seconds).
const maxWorkerLease = 900

var ErrTokenPolicy = errors.New("openbao: token is not a rempart-worker token")

type unwrapResp struct {
	Auth *struct {
		ClientToken   string   `json:"client_token"`
		Policies      []string `json:"policies"`
		TokenPolicies []string `json:"token_policies"`
		LeaseDuration int      `json:"lease_duration"`
	} `json:"auth"`
}

func onlyWorkerPolicy(p []string) bool {
	return len(p) == 1 && p[0] == WorkerPolicy
}

// UnwrapWorkerToken exchanges a single-use wrapping token for the worker
// token (T95): the wrapping token goes in X-Vault-Token only; the unwrapped
// token must carry exactly [WorkerPolicy] and a lease of 1 to 900 s.
func UnwrapWorkerToken(ctx context.Context, addr string, wrapping secret.Value) (secret.Value, error) {
	c, err := NewClient(Config{Addr: addr, Token: wrapping})
	if err != nil {
		return secret.Value{}, err
	}
	var out unwrapResp
	if _, err := c.post(ctx, "unwrap", "/v1/sys/wrapping/unwrap", struct{}{}, &out); err != nil {
		return secret.Value{}, err
	}
	a := out.Auth
	if a == nil || a.ClientToken == "" {
		return secret.Value{}, fmt.Errorf("%w: unwrap: no token in the response", ErrStatus)
	}
	if !onlyWorkerPolicy(a.Policies) || !onlyWorkerPolicy(a.TokenPolicies) {
		return secret.Value{}, ErrTokenPolicy
	}
	if a.LeaseDuration < 1 || a.LeaseDuration > maxWorkerLease {
		return secret.Value{}, fmt.Errorf("%w: unwrap: token lifetime out of bounds", ErrStatus)
	}
	return secret.New(a.ClientToken), nil
}
