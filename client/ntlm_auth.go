package client

import "net/http"

type ntlmAuthenticator struct {
	originalTransport http.RoundTripper
}

func newNTLMRoundTripper(originalTransport http.RoundTripper) *ntlmAuthenticator {
	if originalTransport == nil {
		originalTransport = http.DefaultTransport
	}
	return &ntlmAuthenticator{
		originalTransport: originalTransport,
	}
}
