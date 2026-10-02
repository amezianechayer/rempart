package envelope

import (
	"encoding/binary"

	"github.com/amezianechayer/rempart/internal/tenancy"
)

// Format v1 (docs/plans/M1-envelope-transit.md section 6).
const (
	tenantLen   = 36
	dekIDLen    = 16
	offTenant   = 1
	offDEKID    = offTenant + tenantLen // 37
	offLen      = offDEKID + dekIDLen   // 53
	fixedHeader = offLen + 2            // 55
	nonceSize   = 12
	tagSize     = 16
	maxWrapped  = 1024
	maxSealed   = fixedHeader + nonceSize + maxWrapped + MaxPlaintext + tagSize
)

// Header holds the public fields of a sealed payload, read without decrypting.
type Header struct {
	Version byte
	Tenant  tenancy.ID // checked by tenancy.ParseID
	DEKID   [16]byte
	Wrapped []byte // copy
	Nonce   [12]byte
}

// ParseHeader reads the public fields of a sealed payload: ErrCorrupt if malformed.
func ParseHeader(sealed []byte) (Header, error) {
	h, _, err := parseHeader(sealed)
	return h, err
}

// parseHeader returns the header and its length (the associated data).
func parseHeader(sealed []byte) (Header, int, error) {
	if len(sealed) < fixedHeader || len(sealed) > maxSealed || sealed[0] != FormatV1 {
		return Header{}, 0, ErrCorrupt
	}
	tenant, err := tenancy.ParseID(string(sealed[offTenant:offDEKID]))
	if err != nil {
		return Header{}, 0, ErrCorrupt
	}
	l := int(binary.BigEndian.Uint16(sealed[offLen:fixedHeader]))
	if l < 1 || l > maxWrapped || len(sealed) < fixedHeader+l+nonceSize {
		return Header{}, 0, ErrCorrupt
	}
	h := Header{Version: FormatV1, Tenant: tenant}
	copy(h.DEKID[:], sealed[offDEKID:offLen])
	hlen := fixedHeader + l
	h.Wrapped = append([]byte(nil), sealed[fixedHeader:hlen]...)
	copy(h.Nonce[:], sealed[hlen:hlen+nonceSize])
	return h, hlen, nil
}

// buildHeader returns version | tenant | DEK id | len(wrapped) | wrapped.
func buildHeader(tenant tenancy.ID, id [16]byte, wrapped []byte) []byte {
	h := make([]byte, 0, fixedHeader+len(wrapped))
	h = append(h, FormatV1)
	h = append(h, tenant...)
	h = append(h, id[:]...)
	h = binary.BigEndian.AppendUint16(h, uint16(len(wrapped))) //nolint:gosec // G115: len(wrapped) is checked to be at most 1024.
	return append(h, wrapped...)
}
