//go:build !windows

package client

import "net/http"

func (n *ntlmAuthenticator) AuthenticateRequest(req *http.Request) error {
	panic("NTLM authentication is only implemented on Windows")
}
