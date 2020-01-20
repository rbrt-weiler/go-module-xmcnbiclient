package xmcnbiclient

import "testing"

func TestNew(t *testing.T) {
	hostname := "example.com"
	c := New(hostname)
	if c.AccessScheme != AccessSchemeHTTPS {
		t.Errorf("New() returned client with AccessScheme != HTTPS")
	}
	if c.HTTPHost != hostname {
		t.Errorf("New() did not set HTTPHost correctly")
	}
	if c.HTTPPort != 8443 {
		t.Errorf("New() did not set HTTPPort correctly")
	}
	if c.Authentication.Type != "" {
		t.Errorf("New() did not provide empty authentication (Type)")
	}
	if c.Authentication.UserID != "" {
		t.Errorf("New() did not provide empty authentication (UserID)")
	}
	if c.Authentication.Secret != "" {
		t.Errorf("New() did not provide empty authentication (Secret)")
	}
	if c.AccessToken.RawToken != "" {
		t.Errorf("New() did not set an empty OAuth token")
	}
}
