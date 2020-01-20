package xmcnbiclient

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

const (
	AccessSchemeHTTP  string = "http"
	AccessSchemeHTTPS string = "https"
	AuthTypeBasic     string = "basic"
	AuthTypeOAuth     string = "oauth"
)

type Authentication struct {
	Type   string
	UserID string
	Secret string
}

type nbiClient struct {
	httpClient     http.Client
	accessScheme   string
	httpHost       string
	httpPort       uint
	authentication Authentication
	accessToken    OAuthToken
}

func New(host string) nbiClient {
	var c nbiClient
	c.httpClient = http.Client{}
	c.UseHTTPS()
	c.httpHost = host
	c.SetPort(8443)
	c.AllowInsecureHTTPS(false)
	c.SetTimeout(5)
	c.UseBasicAuth("root", "abc123")
	return c
}

func (c nbiClient) String() string {
	return fmt.Sprintf("%s://%s{%s:***}@%s:%d/", c.accessScheme, c.authentication.Type, c.authentication.UserID, c.httpHost, c.httpPort)
}

func (c *nbiClient) UseHTTP() {
	c.accessScheme = AccessSchemeHTTP
}

func (c *nbiClient) UseHTTPS() {
	c.accessScheme = AccessSchemeHTTPS
}

func (c *nbiClient) SetPort(port uint) (bool, error) {
	if 1 <= port && 65535 >= port {
		c.httpPort = port
		return true, nil
	}
	return false, fmt.Errorf("port out of range (1 - 65535)")
}

func (c *nbiClient) SetTimeout(seconds uint) (bool, error) {
	if 1 <= seconds && 300 >= seconds {
		c.httpClient.Timeout = time.Second * time.Duration(seconds)
		return true, nil
	}
	return false, fmt.Errorf("timeout out of range (1 - 300)")
}

func (c *nbiClient) AllowInsecureHTTPS(allow bool) {
	httpTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: allow},
	}
	c.httpClient.Transport = httpTransport
}

func (c *nbiClient) UseBasicAuth(username string, password string) {
	c.authentication = Authentication{Type: AuthTypeBasic, UserID: username, Secret: password}
}

func (c *nbiClient) UseOAuth(clientid string, secret string) {
	c.authentication = Authentication{Type: AuthTypeOAuth, UserID: clientid, Secret: secret}
}

func (c *nbiClient) BaseURL() string {
	return fmt.Sprintf("%s://%s:%d", c.accessScheme, c.httpHost, c.httpPort)
}

func (c *nbiClient) TokenURL() string {
	return fmt.Sprintf("%s/oauth/token/access-token?grant_type=client_credentials", c.BaseURL())
}

func (c *nbiClient) APIURL() string {
	return fmt.Sprintf("%s/nbi/graphql", c.BaseURL())
}

func (c *nbiClient) RetrieveOAuthToken() error {
	var tokenData OAuthToken

	if c.authentication.Type != AuthTypeOAuth {
		return fmt.Errorf("auth type not set to OAuth")
	}

	// Generate an actual HTTP request.
	req, reqErr := http.NewRequest(http.MethodPost, c.TokenURL(), nil)
	if reqErr != nil {
		return fmt.Errorf("could not create HTTPS request: %s", reqErr)
	}
	req.Header.Set("User-Agent", httpUserAgent)
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Accept", jsonMimeType)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.authentication.UserID, c.authentication.Secret)

	// Try to get a result from the API.
	res, resErr := c.httpClient.Do(req)
	if resErr != nil {
		return fmt.Errorf("could not connect to XMC: %s", resErr)
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("got status code %d instead of 200", res.StatusCode)
	}
	defer res.Body.Close()

	// Check if the HTTP response has yielded the expected content type.
	resContentType := res.Header.Get("Content-Type")
	if strings.Index(resContentType, jsonMimeType) != 0 {
		return fmt.Errorf("Content-Type %s returned instead of %s", resContentType, jsonMimeType)
	}

	// Read and parse the body of the HTTP response.
	xmcToken, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		return fmt.Errorf("could not read server response: %s", readErr)
	}
	jsonErr := json.Unmarshal(xmcToken, &tokenData)
	if jsonErr != nil {
		return fmt.Errorf("could not read server response: %s", jsonErr)
	}

	decodeErr := tokenData.Decode()
	if decodeErr != nil {
		return fmt.Errorf("could not decode token: %s", decodeErr)
	}

	c.accessToken = tokenData

	return nil
}

func (c *nbiClient) OAuthToken() OAuthToken {
	return c.accessToken
}

func (c *nbiClient) QueryAPI(query string) (string, error) {
	jsonQuery, jsonQueryErr := json.Marshal(map[string]string{"query": query})
	if jsonQueryErr != nil {
		return "", fmt.Errorf("could not encode query into JSON: %s", jsonQueryErr)
	}
	req, reqErr := http.NewRequest(http.MethodPost, c.APIURL(), bytes.NewBuffer(jsonQuery))
	if reqErr != nil {
		return "", fmt.Errorf("could not create HTTP(S) request: %s", reqErr)
	}
	req.Header.Set("User-Agent", httpUserAgent)
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Content-Type", jsonMimeType)
	req.Header.Set("Accept", jsonMimeType)
	if c.authentication.Type == AuthTypeOAuth {
		if c.accessToken.IsValid() != true {
			tokenErr := c.RetrieveOAuthToken()
			if tokenErr != nil {
				return "", fmt.Errorf("could not retrieve fresh OAuth token: %s", tokenErr)
			}
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.accessToken.AccessToken))
	} else {
		req.SetBasicAuth(c.authentication.UserID, c.authentication.Secret)
	}

	// Try to get a result from the API.
	res, resErr := c.httpClient.Do(req)
	if resErr != nil {
		return "", fmt.Errorf("Could not connect to XMC: %s", resErr)
	}
	if res.StatusCode != 200 {
		return "", fmt.Errorf("Got status code %d instead of 200", res.StatusCode)
	}
	defer res.Body.Close()

	// Check if the HTTP response has yielded the expected content type.
	resContentType := res.Header.Get("Content-Type")
	if strings.Index(resContentType, jsonMimeType) != 0 {
		return "", fmt.Errorf("Content-Type %s returned instead of %s", resContentType, jsonMimeType)
	}

	// Read the body of the HTTP response.
	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		return "", fmt.Errorf("Could not read server response: %s", readErr)
	}

	return string(body), nil
}
