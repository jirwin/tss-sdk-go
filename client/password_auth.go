package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const tokenPath = "/oauth2/token"

type tokenError struct {
	Error string `json:"error"`
}

type tokenResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type passwordTokenSource struct {
	baseURL  string
	username string
	password string
}

func (p *passwordTokenSource) Token() (*oauth2.Token, error) {
	values := url.Values{
		"username":   {p.username},
		"password":   {p.password},
		"grant_type": {"password"},
	}

	body := strings.NewReader(values.Encode())
	requestUrl, err := url.Parse(p.baseURL)
	if err != nil {
		return nil, err
	}
	requestUrl.Scheme = "https"
	requestUrl.Path = tokenPath

	res, err := http.Post(requestUrl.String(), "application/x-www-form-urlencoded", body)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		tErr := &tokenError{}
		if err := json.Unmarshal(data, tErr); err == nil {
			return nil, fmt.Errorf("error getting token: %s", tErr.Error)
		}
		return nil, fmt.Errorf("received non-200 response during token grant")
	}

	grant := &tokenResp{}
	err = json.Unmarshal(data, grant)
	if err != nil {
		return nil, err
	}

	return &oauth2.Token{
		AccessToken:  grant.AccessToken,
		TokenType:    grant.TokenType,
		RefreshToken: grant.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(grant.ExpiresIn) * time.Second),
	}, nil
}

type passwordAuth struct {
	originalTransport http.RoundTripper
	tokenSource       oauth2.TokenSource
}

func (p *passwordAuth) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := p.tokenSource.Token()
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	return p.originalTransport.RoundTrip(req)
}

func newPasswordRoundTripper(baseURL, username, password string, originalTransport http.RoundTripper) *passwordAuth {
	passwordTs := &passwordTokenSource{
		baseURL:  baseURL,
		username: username,
		password: password,
	}

	return &passwordAuth{
		tokenSource:       oauth2.ReuseTokenSource(nil, passwordTs),
		originalTransport: originalTransport,
	}
}
