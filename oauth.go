package xmcnbiclient

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// OAuthHeaderElements stores all fields contained in the decoded header part of the raw OAuth token.
type OAuthHeaderElements struct {
	RawHeader string `json:"-"`
	Algorithm string `json:"alg"`
}

// OAuthPayloadElements stores all fields contained in the decoded payload part of the raw OAuth token.
type OAuthPayloadElements struct {
	RawPayload       string    `json:"-"`
	Issuer           string    `json:"iss,omitempty"`
	Subject          string    `json:"sub,omitempty"`
	JWTID            string    `json:"jti,omitempty"`
	Roles            []string  `json:"roles,omitempty"`
	IsuedAtUnixfmt   int64     `json:"iat,omitempty"`
	NotBeforeUnixfmt int64     `json:"nbf,omitempty"`
	ExpiresAtUnixfmt int64     `json:"exp,omitempty"`
	IssuedAt         time.Time `json:"-"`
	NotBefore        time.Time `json:"-"`
	ExpiresAt        time.Time `json:"-"`
	LongLived        bool      `json:"longLived,omitempty"`
}

// OAuthToken stores the raw OAuth token returned by XMC as well as the decoded representation.
type OAuthToken struct {
	TokenType string `json:"token_type"`
	RawToken  string `json:"access_token"`
	Header    OAuthHeaderElements
	Payload   OAuthPayloadElements
	Signature []byte
}

// String returns the raw header part of the OAuth token.
func (he OAuthHeaderElements) String() string {
	return he.RawHeader
}

// String returns the raw payload part of the OAuth token.
func (pe OAuthPayloadElements) String() string {
	return pe.RawPayload
}

// String returns the raw OAuth token.
func (t OAuthToken) String() string {
	return t.RawToken
}

// decodeHeader decodes the header part of the raw OAuth token.
func (t *OAuthToken) decodeHeader() error {
	var headerElements OAuthHeaderElements

	rawHeader := strings.Split(t.RawToken, ".")[0]
	headerData, headerErr := base64.RawURLEncoding.DecodeString(rawHeader)
	if headerErr != nil {
		return headerErr
	}
	decodeErr := json.Unmarshal(headerData, &headerElements)
	if decodeErr != nil {
		return decodeErr
	}
	t.Header.RawHeader = rawHeader
	t.Header = headerElements

	return nil
}

// decodePayload decodes the payload part of the raw OAuth token.
func (t *OAuthToken) decodePayload() error {
	var payloadElements OAuthPayloadElements

	rawPayload := strings.Split(t.RawToken, ".")[1]
	payloadData, payloadErr := base64.RawURLEncoding.DecodeString(rawPayload)
	if payloadErr != nil {
		return payloadErr
	}
	decodeErr := json.Unmarshal(payloadData, &payloadElements)
	if decodeErr != nil {
		return decodeErr
	}

	payloadElements.IssuedAt = time.Unix(payloadElements.IsuedAtUnixfmt, 0)
	payloadElements.NotBefore = time.Unix(payloadElements.NotBeforeUnixfmt, 0)
	payloadElements.ExpiresAt = time.Unix(payloadElements.ExpiresAtUnixfmt, 0)

	t.Payload = payloadElements

	return nil
}

// Decode decodes the raw OAuth token into human usable representations.
func (t *OAuthToken) Decode() error {
	headerErr := t.decodeHeader()
	if headerErr != nil {
		return headerErr
	}
	payloadErr := t.decodePayload()
	if payloadErr != nil {
		return payloadErr
	}
	signature, signatureErr := base64.RawURLEncoding.DecodeString(strings.Split(t.RawToken, ".")[2])
	if signatureErr != nil {
		return signatureErr
	}
	t.Signature = signature

	return nil
}

// IsValid returns a boolean representing if the token is still valid (true) or not (false).
func (t *OAuthToken) IsValid() bool {
	if t.RawToken == "" {
		return false
	}
	if t.Payload.ExpiresAt.Before(time.Now()) {
		return false
	}
	return true
}
