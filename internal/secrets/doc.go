// Package secrets holds the per-tenant envelope encryption of Rempart
// (ADR 0001, M1-T01): envelope seals data with AES-256-GCM under a data key
// (DEK) of the tenant, the DEK being wrapped by a KeyWrapper (ports). The
// OpenBao Transit adapter (adapters/openbao) wraps DEKs with the key
// rempart-tenant-<tenant id> (ADR 0004); a fake KeyWrapper serves the tests.
// No key material leaves the process in clear, and a sealed value is bound to
// its tenant.
package secrets
