package xmcnbiclient

import (
	"fmt"
	"testing"
)

const (
	/*
		{
		  "alg": "none"
		}
	*/
	testTokenHeader string = "ewogICJhbGciOiAibm9uZSIKfQ"
	/*
		{
		  "iss": "foobar.example.com",
		  "sub": "XMC",
		  "jti": "foo123bar",
		  "roles": [
		    "foo",
		    "bar"
		  ],
		  "iat": 1579535000,
		  "nbf": 1579535100,
		  "exp": 1579535200,
		  "longLived": false
		}
	*/
	testTokenPayload   string = "ewogICJpc3MiOiAiZm9vYmFyLmV4YW1wbGUuY29tIiwKICAic3ViIjogIlhNQyIsCiAgImp0aSI6ICJmb28xMjNiYXIiLAogICJyb2xlcyI6IFsKICAgICJmb28iLAogICAgImJhciIKICBdLAogICJpYXQiOiAxNTc5NTM1MDAwLAogICJuYmYiOiAxNTc5NTM1MTAwLAogICJleHAiOiAxNTc5NTM1MjAwLAogICJsb25nTGl2ZWQiOiBmYWxzZQp9"
	testTokenSignature string = "nonefoobarnone"
)

var (
	testToken string = fmt.Sprintf("%s.%s.%s", testTokenHeader, testTokenPayload, testTokenSignature)
)

func TestDecode(t *testing.T) {
	var o OAuthToken
	o.RawToken = testToken
	decodeErr := o.Decode()
	if decodeErr != nil {
		t.Errorf("Decode() could not decode test token: %s", decodeErr)
	}
}

func TestIsValid(t *testing.T) {
	var o OAuthToken
	if o.IsValid() {
		t.Errorf("IsValid() returned true for an empty token")
	}
}
