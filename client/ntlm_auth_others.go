//go:build !windows

package client

import "net/http"

func (n *ntlmAuthenticator) RoundTrip(req *http.Request) (*http.Response, error) {
	panic("NTLM authentication is only implemented on Windows")
}
