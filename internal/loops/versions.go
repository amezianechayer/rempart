package loops

// ChangeIDs lists the change ids passed to workflow.GetVersion (D8 of
// M1-codec-replay): any change of the command sequence of a workflow that may
// have runs in flight goes through workflow.GetVersion with an id declared
// here; TestReplay is the mechanical guard. Empty: the continuation of the
// demo needed none (no demo run outlives 228 s, the dev stack is disposable).
var ChangeIDs = []string{}
