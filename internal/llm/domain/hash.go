package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

type canonRequest struct {
	V          int            `json:"v"`
	PromptID   string         `json:"prompt_id"`
	PromptHash string         `json:"prompt_hash"`
	System     string         `json:"system"`
	Messages   []canonMessage `json:"messages"`
	Schema     string         `json:"schema"`
	MaxTokens  int            `json:"max_tokens"`
}

type canonMessage struct {
	Role  string      `json:"role"`
	Parts []canonPart `json:"parts"`
}

type canonPart struct {
	Text      string          `json:"text"`
	Untrusted *canonUntrusted `json:"untrusted"`
}

type canonUntrusted struct {
	SourceID string `json:"source_id"`
	Content  string `json:"content"`
}

// RequestHash is the lower-case hex SHA-256 of the canonical JSON of r (plan M0-T08, P4).
func RequestHash(r Request) string {
	c := canonRequest{
		V:          1,
		PromptID:   r.PromptID,
		PromptHash: r.PromptHash,
		System:     r.System,
		Messages:   make([]canonMessage, 0, len(r.Messages)),
		Schema:     string(r.Schema),
		MaxTokens:  r.MaxTokens,
	}
	for _, m := range r.Messages {
		cm := canonMessage{Role: string(m.Role), Parts: make([]canonPart, 0, len(m.Parts))}
		for _, p := range m.Parts {
			cp := canonPart{Text: p.Text}
			if p.Untrusted != nil {
				cp.Untrusted = &canonUntrusted{SourceID: p.Untrusted.SourceID, Content: p.Untrusted.Content}
			}
			cm.Parts = append(cm.Parts, cp)
		}
		c.Messages = append(c.Messages, cm)
	}
	b, err := json.Marshal(c)
	if err != nil { // unreachable: only strings, ints, slices and pointers
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
