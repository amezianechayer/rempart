package loops

import (
	"testing"
	"time"
)

// TestLoopSpecMaxRunDuration (c): RunLoop is bounded by the wall time budget,
// then by one verification started just before it: MaxActivityAttempts
// attempts of ActivityTimeout each, with a backoff of 1 s then 2 s. The
// default activity timeout applies when ActivityTimeout is zero.
func TestLoopSpecMaxRunDuration(t *testing.T) {
	base := func(activityTimeout time.Duration) LoopSpec {
		return LoopSpec{
			ID: "L0-demo", ProposeActivity: "demo.Propose", VerifyActivity: "demo.Verify",
			Strategies:  []string{"direct", "reformulate"},
			Budget:      Budget{MaxIterations: 4, MaxTokens: 4000, MaxWallTime: time.Minute},
			SwitchAfter: 2, EscalateAfter: 3, ActivityTimeout: activityTimeout,
		}
	}
	cases := []struct {
		name string
		spec LoopSpec
		want time.Duration
	}{
		// Spec of L0-demo: 60 s + 3 x 30 s + 3 s.
		{"demo", base(30 * time.Second), 153 * time.Second},
		// Default activity timeout (5 min): 60 s + 3 x 300 s + 3 s.
		{"default_activity_timeout", base(0), 963 * time.Second},
		{"minimum_activity_timeout", base(MinActivityTimeout), 66 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.spec.MaxRunDuration(); got != tc.want {
				t.Errorf("MaxRunDuration() = %v, want %v", got, tc.want)
			}
		})
	}
	t.Run("value_receiver", func(t *testing.T) {
		s := base(0)
		_ = s.MaxRunDuration()
		if s.ActivityTimeout != 0 || s.SwitchAfter != 2 {
			t.Errorf("MaxRunDuration changed its receiver: %+v", s)
		}
	})
}
