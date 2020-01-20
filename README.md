# Go module xmcnbiclient

xmcnbiclient is a module that interfaces with the Northbound Interface (NBI) of Extreme Management Center (XMC; formerly known as NetSight), the network management solution from Extreme Networks. The module currently provides the following features:

  * Supports HTTP as well as HTTPS access to XMC.
  * Allows setting the TCP port used to connect to XMC to any valid value.
  * Authentication via HTTP Basic Auth or OAuth.
  * Automatic refresh of OAuth tokens during longer sessions.

While the module should be production ready, tests are pending. Use with caution until v1.0.0 has been reached.

## How to use the module

A minimal Go program that uses the module might look as follows.

<pre>
package main

import (
	"fmt"
	"os"

	xmcnbiclient "gitlab.com/rbrt-weiler/go-module-xmcnbiclient"
)

func main() {
	client := xmcnbiclient.New("localhost")
	client.UseBasicAuth("root", "abc123")
	client.AllowInsecureHTTPS(true)
	res, err := client.QueryAPI("query { network { devices { up ip sysName nickName } } }")
	if err != nil {
		fmt.Printf("Oops: %s", err)
		os.Exit(255)
	}
	fmt.Println(res)
	os.Exit(0)
}
</pre>

## Source

The original project is [hosted at GitLab](https://gitlab.com/rbrt-weiler/go-module-xmcnbiclient), with a [copy over at GitHub](https://github.com/rbrt-weiler/go-module-xmcnbiclient) for the folks over there.