//go:build windows

package client

func (n *ntlmAuthenticator) RoundTrip(req *http.Request) (*http.Response, error) {
	return n.originalTransport.RoundTrip(req)
}
