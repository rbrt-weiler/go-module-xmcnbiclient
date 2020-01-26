// Package xmcnbiclient interfaces with the Northbound Interface of Extreme Management Center.
// Using xmcnbiclient, any Go program can connect to XMC, authenticate using either HTTP Basic Auth or OAuth and send API queries and receive the results.
package xmcnbiclient

const (
	moduleName     string = "go-module-xmcnbiclient"
	moduleVersion  string = "0.5.0"
	jsonMimeType   string = "application/json"
	httpMinPort    uint   = 1
	httpMaxPort    uint   = 65535
	httpMinTimeout uint   = 1
	httpMaxTimeout uint   = 300
)
