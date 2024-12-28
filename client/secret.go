package client

import (
	"context"
	"net/http"
	"path"
	"strconv"

	"github.com/jirwin/ctxzap"
	"go.uber.org/zap"

	"github.com/DelineaXPM/tss-sdk-go/v2/secrets"
)

const (
	secretsResource = "secrets"
)

// getSecretURL returns a URL to fetch a secret from the Secret Server
func (s *Client) getSecretURL(ctx context.Context, secretID int) (string, error) {
	baseURL, err := s.getBaseURL(ctx)
	if err != nil {
		return "", err
	}

	baseURL.Path = path.Join(baseURL.Path, secretsResource, strconv.Itoa(secretID))

	return baseURL.String(), nil
}

// Secret gets the secret with id from the Secret Server of the given tenant
func (s *Client) Secret(ctx context.Context, id int) (*secrets.Secret, error) {
	l := ctxzap.Extract(ctx)

	secret := &secrets.Secret{}

	l.Debug("fetching secret", zap.Int("secret_id", id))

	reqURL, err := s.getSecretURL(ctx, id)
	if err != nil {
		return nil, err
	}

	err = s.doRequest(ctx, http.MethodGet, reqURL, nil, secret)
	if err != nil {
		return nil, err
	}

	// automatically download file attachments and substitute them for the
	// (dummy) ItemValue, so as to make the process transparent to the caller
	for index, element := range secret.Fields {
		if element.IsFile && element.FileAttachmentID != 0 && element.Filename != "" {
			fieldURL, err := s.getSecretFieldURL(ctx, id, element.Slug)
			if err != nil {
				return nil, err
			}

			val := ""
			err = s.doRequest(ctx, http.MethodGet, fieldURL, nil, &val)
			if err != nil {
				return nil, err
			}

			secret.Fields[index].ItemValue = val
		}
	}

	return secret, nil
}

func (s *Client) getSecretFieldURL(ctx context.Context, secretID int, fieldSlug string) (string, error) {
	baseURL, err := s.getBaseURL(ctx)
	if err != nil {
		return "", err
	}

	baseURL.Path = path.Join(baseURL.Path, secretsResource, strconv.Itoa(secretID), "fields", fieldSlug)

	return baseURL.String(), nil
}
