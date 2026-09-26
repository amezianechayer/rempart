package ports

import (
	"reflect"
	"testing"
)

// checkMethodSet asserts that typ has exactly the wanted methods with the
// wanted signatures. Signatures are compared as strings so that this test
// does not import the domain package (plan M0-T08, 3.2 rule 2).
func checkMethodSet(t *testing.T, typ reflect.Type, want map[string]string) {
	t.Helper()
	if typ.Kind() != reflect.Interface {
		t.Fatalf("%s is a %s, want an interface", typ, typ.Kind())
	}
	if got := typ.NumMethod(); got != len(want) {
		names := make([]string, 0, got)
		for i := range got {
			names = append(names, typ.Method(i).Name)
		}
		t.Fatalf("%s has %d methods %v, want exactly %d", typ, got, names, len(want))
	}
	for i := range typ.NumMethod() {
		m := typ.Method(i)
		sig, ok := want[m.Name]
		if !ok {
			t.Fatalf("%s has unexpected method %s", typ, m.Name)
		}
		if got := m.Type.String(); got != sig {
			t.Fatalf("%s.%s has signature %q, want %q", typ, m.Name, got, sig)
		}
	}
}

func TestModelProviderMethodSet(t *testing.T) {
	checkMethodSet(t, reflect.TypeFor[ModelProvider](), map[string]string{
		"Capabilities": "func(domain.Route) domain.Capabilities",
		"Structured":   "func(context.Context, domain.Route, domain.Request) (domain.Response, error)",
		"WithTools":    "func(context.Context, domain.Route, domain.Request, []domain.ToolSpec) (domain.Response, error)",
	})
}

func TestRouteResolverMethodSet(t *testing.T) {
	checkMethodSet(t, reflect.TypeFor[RouteResolver](), map[string]string{
		"Resolve": "func(context.Context, tenancy.ID) (domain.TenantPolicy, error)",
	})
}
