package openbao

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"github.com/amezianechayer/rempart/internal/secrets/ports"
	"github.com/amezianechayer/rempart/internal/secrets/secret"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

var mountRe = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

// Transit implements ports.KeyWrapper with OpenBao Transit keys rempart-tenant-<id>.
type Transit struct {
	c     *Client
	mount string
}

var _ ports.KeyWrapper = (*Transit)(nil)

// NewTransit returns a Transit on mount ("" : "transit").
func NewTransit(c *Client, mount string) (*Transit, error) {
	if mount == "" {
		mount = "transit"
	}
	if c == nil || !mountRe.MatchString(mount) {
		return nil, ErrConfig
	}
	return &Transit{c: c, mount: mount}, nil
}

func (t *Transit) path(op string, tenant tenancy.ID) (string, error) {
	id, err := tenancy.ParseID(string(tenant))
	if err != nil {
		return "", fmt.Errorf("openbao: transit %s: %w", op, tenancy.ErrInvalidTenant)
	}
	return "/v1/" + t.mount + "/" + op + "/rempart-tenant-" + string(id), nil
}

type plaintextResp struct {
	Data struct {
		Plaintext  string `json:"plaintext"`
		Ciphertext string `json:"ciphertext"`
	} `json:"data"`
}

func decodeDEK(b64 string) (secret.Bytes, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	defer clear(raw)
	if err != nil || len(raw) != 32 {
		return secret.Bytes{}, errors.New("openbao: transit: data key is not 32 bytes")
	}
	return secret.NewBytes(raw), nil
}

// GenerateDataKey calls datakey/plaintext for the tenant key.
func (t *Transit) GenerateDataKey(ctx context.Context, tenant tenancy.ID) (secret.Bytes, []byte, error) {
	p, err := t.path("datakey/plaintext", tenant)
	if err != nil {
		return secret.Bytes{}, nil, err
	}
	var r plaintextResp
	if _, err := t.c.post(ctx, "datakey", p, map[string]int{"bits": 256}, &r); err != nil {
		return secret.Bytes{}, nil, err
	}
	dek, err := decodeDEK(r.Data.Plaintext)
	if err != nil {
		return secret.Bytes{}, nil, err
	}
	if r.Data.Ciphertext == "" || len(r.Data.Ciphertext) > 1024 {
		dek.Wipe()
		return secret.Bytes{}, nil, errors.New("openbao: transit: wrapped key out of bounds")
	}
	return dek, []byte(r.Data.Ciphertext), nil
}

// UnwrapDataKey calls decrypt for the tenant key; 400 is ports.ErrWrappedKeyRejected.
func (t *Transit) UnwrapDataKey(ctx context.Context, tenant tenancy.ID, wrapped []byte) (secret.Bytes, error) {
	p, err := t.path("decrypt", tenant)
	if err != nil {
		return secret.Bytes{}, err
	}
	if len(wrapped) < 1 || len(wrapped) > 1024 {
		return secret.Bytes{}, ports.ErrWrappedKeyRejected
	}
	var r plaintextResp
	code, err := t.c.post(ctx, "decrypt", p, map[string]string{"ciphertext": string(wrapped)}, &r)
	switch {
	case code == http.StatusBadRequest:
		return secret.Bytes{}, ports.ErrWrappedKeyRejected
	case err != nil:
		return secret.Bytes{}, err
	}
	return decodeDEK(r.Data.Plaintext)
}
