package client

import "net/http"

type ntlmAuthenticator struct {
	originalTransport http.RoundTripper
}

func (n *ntlmAuthenticator) RoundTrip(request *http.Request) (*http.Response, error) {
	//TODO implement me
	panic("implement me")
}

func newNTLMRoundTripper(originalTransport http.RoundTripper) *ntlmAuthenticator {
	return &ntlmAuthenticator{
		originalTransport: originalTransport,
	}
}
