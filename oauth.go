package xmcnbiclient

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type oAuthHeaderElements struct {
	Algorithm string `json:"alg"`
}

type oAuthPayloadElements struct {
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

type OAuthToken struct {
	TokenType   string `json:"token_type"`
	AccessToken string `json:"access_token"`
	Header      oAuthHeaderElements
	Payload     oAuthPayloadElements
	Signature   []byte
}

func (t OAuthToken) String() string {
	return fmt.Sprintf("%s", t.AccessToken)
}

func (t *OAuthToken) decodeHeader() error {
	var headerElements oAuthHeaderElements

	headerData, headerErr := base64.RawURLEncoding.DecodeString(strings.Split(t.AccessToken, ".")[0])
	if headerErr != nil {
		return headerErr
	}
	decodeErr := json.Unmarshal(headerData, &headerElements)
	if decodeErr != nil {
		return decodeErr
	}
	t.Header = headerElements

	return nil
}

func (t *OAuthToken) decodePayload() error {
	var payloadElements oAuthPayloadElements

	payloadData, payloadErr := base64.RawURLEncoding.DecodeString(strings.Split(t.AccessToken, ".")[1])
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

func (t *OAuthToken) Decode() error {
	headerErr := t.decodeHeader()
	if headerErr != nil {
		return headerErr
	}
	payloadErr := t.decodePayload()
	if payloadErr != nil {
		return payloadErr
	}
	signature, signatureErr := base64.RawURLEncoding.DecodeString(strings.Split(t.AccessToken, ".")[2])
	if signatureErr != nil {
		return signatureErr
	}
	t.Signature = signature

	return nil
}

func (t *OAuthToken) IsValid() bool {
	if t.AccessToken == "" {
		return false
	}
	if t.Payload.ExpiresAt.Before(time.Now()) {
		return false
	}
	return true
}
