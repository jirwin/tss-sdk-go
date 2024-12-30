//go:build windows

package client

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"

	"github.com/alexbrainman/sspi/ntlm"
)

func (n *ntlmAuthenticator) doReq(req *http.Request) (*http.Response, string, error) {
	resp, err := n.originalTransport.RoundTrip(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}

	return resp, string(body), nil
}

func (n *ntlmAuthenticator) checkNTLM(req *http.Request) error {
	authReq, err := http.NewRequest("GET", req.URL.String(), nil)
	if err != nil {
		return err
	}

	res, _, err := n.doReq(authReq)
	if err != nil {
		return err
	}

	if res.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("Unauthorized expected, but got %v", res.StatusCode)
	}

	authHeaders, found := res.Header["Www-Authenticate"]
	if !found {
		return fmt.Errorf("Www-Authenticate not found")
	}

	for _, h := range authHeaders {
		if h == "NTLM" {
			return nil
		}
	}

	return fmt.Errorf("Www-Authenticate header does not contain NTLM, but has %v", authHeaders)
}

func (n *ntlmAuthenticator) doNTLMNegotiate(req *http.Request, negotiate []byte) ([]byte, error) {
	authReq, err := http.NewRequest("GET", req.URL.String(), nil)
	if err != nil {
		return nil, err
	}

	authReq.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(negotiate))

	res, _, err := n.doReq(authReq)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusUnauthorized {
		return nil, fmt.Errorf("Unauthorized expected, but got %v", res.StatusCode)
	}

	authHeaders, found := res.Header["Www-Authenticate"]
	if !found {
		return nil, fmt.Errorf("Www-Authenticate not found")
	}

	if len(authHeaders) != 1 {
		return nil, fmt.Errorf("Only one Www-Authenticate header expected, but %d found: %v", len(authHeaders), authHeaders)
	}

	if len(authHeaders[0]) < 6 {
		return nil, fmt.Errorf("Www-Authenticate header is to short: %q", authHeaders[0])
	}

	if !strings.HasPrefix(authHeaders[0], "NTLM ") {
		return nil, fmt.Errorf("Www-Authenticate header is suppose to starts with \"NTLM \", but is %q", authHeaders[0])
	}

	authenticate, err := base64.StdEncoding.DecodeString(authHeaders[0][5:])
	if err != nil {
		return nil, err
	}

	return authenticate, nil
}

func (n *ntlmAuthenticator) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasPrefix(req.URL.Path, "/api/v1") {
		req.URL.Path = path.Join("/winauthwebservices", req.URL.Path)
	}

	cred, err := ntlm.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, err
	}
	defer cred.Release()

	secctx, negotiate, err := ntlm.NewClientContext(cred)
	if err != nil {
		return nil, err
	}
	defer secctx.Release()

	err = n.checkNTLM(req)
	if err != nil {
		return nil, err
	}

	challenge, err := n.doNTLMNegotiate(req, negotiate)
	if err != nil {
		return nil, err
	}

	authenticate, err := secctx.Update(challenge)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(authenticate))

	return n.originalTransport.RoundTrip(req)
}
