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
	// AccessSchemeHTTP is used to define that HTTP shall be used for communication with XMC.
	AccessSchemeHTTP string = "http"
	// AccessSchemeHTTPS is used to define that HTTPS shall be used for communication with XMC.
	AccessSchemeHTTPS string = "https"
	// AuthTypeBasic is used to define that basic auth shall be used for authentication with XMC.
	AuthTypeBasic string = "basic"
	// AuthTypeOAuth is used to define that OAuth shall be used for authentication with XMC.
	AuthTypeOAuth string = "oauth"
)

// Authentication stores credentials to use when authenticating with XMC.
type Authentication struct {
	// Type must be set to either AuthTypeBasic or AuthTypeOAuth.
	Type string
	// UserID stores the username (basic auth) or client ID (OAuth).
	UserID string
	// Secret stores the password (basic auth) or client secret (OAuth).
	Secret string
}

// NBIClient encapsulates the actual HTTP client that communicates with XMC.
// Use New() to obtain an usable instance. All fields should be treated as read-only; functions are provided where changes shall be possible.
type NBIClient struct {
	// httpClient is the actual HTTP client. Should not be manipulated directly.
	httpClient http.Client
	// UserAgent is transmitted as the User-Agent header with each request.
	UserAgent string
	// AccessScheme is used to define whether HTTP or HTTPS shall be used for communication with XMC.
	AccessScheme string
	// HTTPHost is the IP or hostname of the XMC server. Should not be manipulated directly.
	HTTPHost string
	// HTTPPort is the TCP port where XMC is listening.
	HTTPPort uint
	// Authentication stores authentication information.
	Authentication Authentication
	// AccessToken is used to store the OAuth token when it is used.
	AccessToken OAuthToken
}

// New is used to create an usable instance of NBIClient.
// By default a new instance will use HTTPS to port 8443 with strict certificate checking. The HTTP timeout is set to 5 seconds. Authentication must be set manually before trying to send a query to XMC.
func New(host string) NBIClient {
	var c NBIClient
	c.httpClient = http.Client{}
	c.SetUserAgent(fmt.Sprintf("%s/%s", moduleName, moduleVersion))
	c.UseHTTPS()
	c.HTTPHost = host
	c.SetPort(8443)
	c.UseSecureHTTPS()
	c.SetTimeout(5)
	return c
}

// String returns a compact representation of the authentication method and values with a masked secret.
func (a Authentication) String() string {
	return fmt.Sprintf("%s{%s:%s}", a.Type, a.UserID, "***")
}

// StringWithSecret returns a compact representation of the authentication method and values with the plain text secret.
func (a Authentication) StringWithSecret() string {
	return fmt.Sprintf("%s{%s:%s}", a.Type, a.UserID, a.Secret)
}

// String returns a usable string reprensentation of a NBIClient instance.
func (c NBIClient) String() string {
	return fmt.Sprintf("%s://%s@%s:%d/", c.AccessScheme, c.Authentication, c.HTTPHost, c.HTTPPort)
}

// SetUserAgent sets the User-Agent HTTP header.
func (c *NBIClient) SetUserAgent(ua string) {
	c.UserAgent = ua
}

// UseHTTP sets the protocol to HTTP for the NBIClient instance.
func (c *NBIClient) UseHTTP() {
	c.AccessScheme = AccessSchemeHTTP
}

// UseHTTPS sets the protocol to HTTPS for the NBIClient instance.
func (c *NBIClient) UseHTTPS() {
	c.AccessScheme = AccessSchemeHTTPS
}

// SetPort sets the TCP port where XMC is listening for the NBIClient instance.
func (c *NBIClient) SetPort(port uint) error {
	if httpMinPort <= port && httpMaxPort >= port {
		c.HTTPPort = port
		return nil
	}
	return fmt.Errorf("port out of range (1 - 65535)")
}

// SetTimeout sets the HTTP timeout in seconds for the NBIClient instance.
func (c *NBIClient) SetTimeout(seconds uint) error {
	if httpMinTimeout <= seconds && httpMaxTimeout >= seconds {
		c.httpClient.Timeout = time.Second * time.Duration(seconds)
		return nil
	}
	return fmt.Errorf("timeout out of range (1 - 300)")
}

// UseSecureHTTPS enforces strict HTTPS certificate checking.
func (c *NBIClient) UseSecureHTTPS() {
	httpTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	}
	c.httpClient.Transport = httpTransport
}

// UseInsecureHTTPS disables strict HTTPS certificate checking.
func (c *NBIClient) UseInsecureHTTPS() {
	httpTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	c.httpClient.Transport = httpTransport
}

// UseBasicAuth informs the NBIClient instance to use HTTP Basic Auth along with the provided credentials.
func (c *NBIClient) UseBasicAuth(username string, password string) {
	c.Authentication = Authentication{Type: AuthTypeBasic, UserID: username, Secret: password}
}

// UseOAuth informs the NBIClient instance to use OAuth along with the provided credentials.
func (c *NBIClient) UseOAuth(clientid string, secret string) {
	c.Authentication = Authentication{Type: AuthTypeOAuth, UserID: clientid, Secret: secret}
}

// BaseURL returns the base URL the instance of NBIClient uses to contact XMC.
func (c *NBIClient) BaseURL() string {
	return fmt.Sprintf("%s://%s:%d", c.AccessScheme, c.HTTPHost, c.HTTPPort)
}

// TokenURL returns the URL the instance of NBIClient uses for obtaining an OAuth token.
func (c *NBIClient) TokenURL() string {
	return fmt.Sprintf("%s/oauth/token/access-token?grant_type=client_credentials", c.BaseURL())
}

// APIURL returns the URL the instance of NBIClient sends queries to.
func (c *NBIClient) APIURL() string {
	return fmt.Sprintf("%s/nbi/graphql", c.BaseURL())
}

// RetrieveOAuthToken tries to obtain a valid OAuth token from XMC and to decode it.
func (c *NBIClient) RetrieveOAuthToken() error {
	// Empty token structure to start with.
	var tokenData OAuthToken

	// Only continue if OAuth is actually configured.
	if c.Authentication.Type != AuthTypeOAuth {
		return fmt.Errorf("auth type not set to OAuth")
	}

	// Generate an actual HTTP request.
	req, reqErr := http.NewRequest(http.MethodPost, c.TokenURL(), nil)
	if reqErr != nil {
		return fmt.Errorf("could not create HTTP(S) request: %s", reqErr)
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Accept", jsonMimeType)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.Authentication.UserID, c.Authentication.Secret)

	// Try to get a result from the API.
	res, resErr := c.httpClient.Do(req)
	if resErr != nil {
		return fmt.Errorf("could not connect to XMC: %s", resErr)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("got status code %d instead of %d", res.StatusCode, http.StatusOK)
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

	// Decode token data.
	decodeErr := tokenData.Decode()
	if decodeErr != nil {
		return fmt.Errorf("could not decode token: %s", decodeErr)
	}

	// Store the complete token in the client.
	c.AccessToken = tokenData

	return nil
}

// QueryAPI sends a request to the XMC API and returns the JSON result as a string.
func (c *NBIClient) QueryAPI(query string) (string, error) {
	// Only continue if an authentication method has been defined.
	if c.Authentication.Type == "" {
		return "", fmt.Errorf("no authentication method defined")
	}

	// Wrap the query into a JSON object.
	jsonQuery, jsonQueryErr := json.Marshal(map[string]string{"query": query})
	if jsonQueryErr != nil {
		return "", fmt.Errorf("could not encode query into JSON: %s", jsonQueryErr)
	}
	// Create an HTTP request.
	req, reqErr := http.NewRequest(http.MethodPost, c.APIURL(), bytes.NewBuffer(jsonQuery))
	if reqErr != nil {
		return "", fmt.Errorf("could not create HTTP(S) request: %s", reqErr)
	}
	// Set some basic request headers.
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Content-Type", jsonMimeType)
	req.Header.Set("Accept", jsonMimeType)
	// Set the authentication header based on the chosen authentication method.
	if c.Authentication.Type == AuthTypeOAuth {
		// If the stored OAuth token is invalid, try to renew it.
		if c.AccessToken.IsValid() != true {
			tokenErr := c.RetrieveOAuthToken()
			if tokenErr != nil {
				return "", fmt.Errorf("could not retrieve fresh OAuth token: %s", tokenErr)
			}
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.AccessToken.RawToken))
	} else {
		req.SetBasicAuth(c.Authentication.UserID, c.Authentication.Secret)
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
