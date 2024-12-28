package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/jirwin/ctxzap"
	"go.uber.org/zap"
)

type ClientOption func(c *Client)

func WithPasswordAuth(username, password string) ClientOption {
	return func(c *Client) {
		transport := c.httpClient.Transport
		if transport == nil {
			transport = http.DefaultTransport
		}
		c.httpClient.Transport = newPasswordRoundTripper(c.baseURL, username, password, transport)
	}
}

func WithNTLMAuth() ClientOption {
	return func(c *Client) {
		transport := c.httpClient.Transport
		if transport == nil {
			transport = http.DefaultTransport
		}
		c.httpClient.Transport = newNTLMRoundTripper(transport)
	}
}

type Client struct {
	baseURL    string
	httpClient *http.Client
}

func New(baseURL string, httpClient *http.Client, opts ...ClientOption) (*Client, error) {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 10 * time.Second,
		}
	}
	c := &Client{
		baseURL:    baseURL,
		httpClient: httpClient,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

// accessResource uses the accessToken to access the API resource.
// It assumes an appropriate combination of method, resource, path and input.
func (s *Client) doRequest(ctx context.Context, method string, reqURL string, input interface{}, output interface{}) error {
	l := ctxzap.Extract(ctx)

	var body io.Reader
	if input != nil {
		if data, err := json.Marshal(input); err == nil {
			body = bytes.NewBuffer(data)
		} else {
			l.Error("error marshaling the request body to JSON", zap.Error(err))
			return err
		}
	}

	req, err := http.NewRequest(method, reqURL, body)
	if err != nil {
		l.Error(
			"error creating request",
			zap.String("method", method),
			zap.String("url", reqURL),
			zap.Error(err),
		)
		return err
	}

	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		req.Header.Set("Content-Type", "application/json")
	}

	l.Debug("calling API", zap.String("method", method), zap.String("url", req.URL.String()))

	resp, err := s.httpClient.Do(req)
	if err != nil {
		l.Error("error making request", zap.Error(err))
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err = fmt.Errorf("error response from API (status_code: %s)", resp.Status)

		errBody, errRead := io.ReadAll(resp.Body)
		if err != nil {
			l.Error("error reading error response body", zap.Error(err))
			return errors.Join(err, errRead)
		}

		l.Error("error response from API", zap.Int("status_code", resp.StatusCode), zap.String("error_body", string(errBody)))
		return err
	}

	if output == nil {
		return nil
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		l.Error("error reading response body", zap.Error(err))
		return err
	}

	switch output.(type) {
	case *string:
		output = string(data)
	default:
		err = json.Unmarshal(data, output)
		if err != nil {
			l.Error("error parsing response body", zap.Error(err))
			return err
		}
	}

	return nil
}

// getBaseURL returns a base URL to build API requests with
func (s *Client) getBaseURL(ctx context.Context) (*url.URL, error) {
	ret, err := url.Parse(s.baseURL)
	if err != nil {
		ctxzap.Extract(ctx).Error("error parsing base URL", zap.Error(err))
		return nil, err
	}

	ret.Scheme = "https"
	ret.Path = "/api/v1"

	return ret, nil
}
