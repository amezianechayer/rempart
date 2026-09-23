# Arborescence hexagonale : exemple du domaine `inventory`

```
internal/inventory/
  domain/
    resource.go        # type Resource, logique pure de normalisation
    resource_test.go
  ports/
    collector.go       # interface Collector
  adapters/
    aws/collector.go   # implémentation AWS SDK v2, lecture seule
    azure/collector.go
  fake/
    collector.go       # faux déterministe alimenté par testdata/
  service.go           # orchestration : dépend des ports uniquement
  service_test.go      # utilise fake/
  testdata/
```

```go
// ports/collector.go
package ports

import (
	"context"

	"example.com/rempart/internal/inventory/domain"
)

type Collector interface {
	// Collect lit l'inventaire d'un compte. Ne doit JAMAIS effectuer d'appel en écriture.
	Collect(ctx context.Context, account domain.AccountRef) ([]domain.Resource, error)
}
```

```go
// fake/collector.go
package fake

type Collector struct {
	Resources map[string][]domain.Resource // par account_id
	Err       error
}

func (f *Collector) Collect(_ context.Context, a domain.AccountRef) ([]domain.Resource, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return f.Resources[a.ID], nil
}
```

Règle : `service.go` et `domain/` ne doivent importer aucun paquet de `adapters/`. Vérifié par un test d'architecture (`go list -deps` ou `arch-go`) dans `make verify-quick`.
