package demo

import (
	"testing"

	"go.temporal.io/sdk/workflow"
)

// TestContinuedRequiresContinuation (security review of the M1 close, T18):
// ContinuedExecutionRunID is also set by a retry or a cron run, whose input
// is the one of the client; only a first attempt without cron schedule is a
// continuation of run 1. A retry or a cron run is never played by the test
// environment of the SDK, hence a test of the predicate.
func TestContinuedRequiresContinuation(t *testing.T) {
	for name, tc := range map[string]struct {
		info workflow.Info
		want bool
	}{
		"continuation":       {workflow.Info{ContinuedExecutionRunID: "run-1", Attempt: 1}, true},
		"no_previous_run":    {workflow.Info{Attempt: 1}, false},
		"retry":              {workflow.Info{ContinuedExecutionRunID: "run-1", Attempt: 2}, false},
		"cron_run":           {workflow.Info{ContinuedExecutionRunID: "run-1", Attempt: 1, CronSchedule: "* * * * *"}, false},
		"attempt_zero":       {workflow.Info{ContinuedExecutionRunID: "run-1"}, false},
		"retry_of_cron_run":  {workflow.Info{ContinuedExecutionRunID: "run-1", Attempt: 3, CronSchedule: "@every 1m"}, false},
		"first_run_cron_set": {workflow.Info{Attempt: 1, CronSchedule: "* * * * *"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			info := tc.info
			if got := continued(&info); got != tc.want {
				t.Errorf("continued(%+v) = %v, want %v", info, got, tc.want)
			}
		})
	}
	if !cronRun(&workflow.Info{CronSchedule: "* * * * *"}) || cronRun(&workflow.Info{}) {
		t.Error("cronRun does not tell a cron run from a plain run")
	}
}
