package loops

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
)

// ErrInvalidLoopID: the loop identifier is not 1 to MaxLoopIDBytes bytes of
// [a-z0-9-], without a leading or trailing hyphen. It never quotes the input.
var ErrInvalidLoopID = errors.New("loops: invalid loop id")

// MaxLoopIDBytes: a tenant id (36 bytes) never fits (T14).
const MaxLoopIDBytes = 32

const loopIDBytes = "abcdefghijklmnopqrstuvwxyz0123456789-"

// NewWorkflowID returns "<loopID>-<uuid v4>" from crypto/rand: no tenant, no customer content.
func NewWorkflowID(loopID string) (string, error) {
	if loopID == "" || len(loopID) > MaxLoopIDBytes || strings.Trim(loopID, loopIDBytes) != "" ||
		loopID[0] == '-' || loopID[len(loopID)-1] == '-' {
		return "", ErrInvalidLoopID
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return loopID + "-" + h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}
