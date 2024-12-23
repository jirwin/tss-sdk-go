package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jirwin/ctxzap"
	"go.uber.org/zap"
)

const (
	cloudBaseURLTemplate string = "https://%s.secretservercloud.%s/"
	defaultAPIPathURI    string = "/api/v1"
	defaultTokenPathURI  string = "/oauth2/token"
	defaultTLD           string = "com"
)

// UserCredential holds the username and password that the API should use to
// authenticate to the REST API
type UserCredential struct {
	Domain, Username, Password, Token string
}

// Configuration settings for the API
type Configuration struct {
	Credentials                                      UserCredential
	ServerURL, TLD, Tenant, apiPathURI, tokenPathURI string
	TLSClientConfig                                  *tls.Config
}

// Server provides access to secrets stored in Delinea Secret Server
type Server struct {
	Configuration
	httpClient *http.Client
}

type ServerOption func(server *Server)

func WithHttpClient(client *http.Client) ServerOption {
	return func(server *Server) {
		server.httpClient = client
	}
}

type TokenCache struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// New returns an initialized Secrets object
func New(config Configuration, opts ...ServerOption) (*Server, error) {
	if config.ServerURL == "" && config.Tenant == "" || config.ServerURL != "" && config.Tenant != "" {
		return nil, fmt.Errorf("either ServerURL of Secret Server/Platform or Tenant of Secret Server Cloud must be set")
	}
	if config.TLD == "" {
		config.TLD = defaultTLD
	}

	if config.apiPathURI == "" {
		config.apiPathURI = defaultAPIPathURI
	}
	config.apiPathURI = strings.Trim(config.apiPathURI, "/")
	if config.tokenPathURI == "" {
		config.tokenPathURI = defaultTokenPathURI
	}
	config.tokenPathURI = strings.Trim(config.tokenPathURI, "/")

	server := &Server{
		Configuration: config,
	}
	for _, opt := range opts {
		opt(server)
	}

	if server.httpClient == nil {
		server.httpClient = &http.Client{}
	}

	if config.TLSClientConfig != nil {
		server.httpClient.Transport.(*http.Transport).TLSClientConfig = config.TLSClientConfig
	}

	return server, nil
}

// urlFor is the URL for the given resource and path
func (s *Server) urlFor(ctx context.Context, resource, path string) string {
	var baseURL string

	if s.ServerURL == "" {
		baseURL = fmt.Sprintf(cloudBaseURLTemplate, s.Tenant, s.TLD)
	} else {
		baseURL = s.ServerURL
	}

	switch {
	case resource == "token":
		return fmt.Sprintf("%s/%s",
			strings.Trim(baseURL, "/"),
			strings.Trim(s.tokenPathURI, "/"))
	default:
		return fmt.Sprintf("%s/%s/%s/%s",
			strings.Trim(baseURL, "/"),
			strings.Trim(s.apiPathURI, "/"),
			strings.Trim(resource, "/"),
			strings.Trim(path, "/"))
	}
}

func (s *Server) urlForSearch(ctx context.Context, resource, searchText, fieldName string) string {
	var baseURL string

	if s.ServerURL == "" {
		baseURL = fmt.Sprintf(cloudBaseURLTemplate, s.Tenant, s.TLD)
	} else {
		baseURL = s.ServerURL
	}
	switch {
	case resource == "secrets":
		url := fmt.Sprintf("%s/%s/%s?paging.filter.searchText=%s&paging.filter.searchField=%s&paging.filter.doNotCalculateTotal=true&paging.take=30&&paging.skip=0",
			strings.Trim(baseURL, "/"),
			strings.Trim(s.apiPathURI, "/"),
			strings.Trim(resource, "/"),
			searchText,
			fieldName)
		if fieldName == "" {
			return fmt.Sprintf("%s%s", url, "&paging.filter.extendedFields=Machine&paging.filter.extendedFields=Notes&paging.filter.extendedFields=Username")
		}
		return fmt.Sprintf("%s%s", url, "&paging.filter.isExactMatch=true")
	default:
		return ""
	}
}

// accessResource uses the accessToken to access the API resource.
// It assumes an appropriate combination of method, resource, path and input.
func (s *Server) accessResource(ctx context.Context, method, resource, path string, input interface{}) ([]byte, error) {
	l := ctxzap.Extract(ctx)

	switch resource {
	case "secrets":
	case "secret-templates":
	default:
		message := "unknown resource"

		l.Error("error accessing resource", zap.String("message", message), zap.String("resource", resource))
		return nil, errors.New(message)
	}

	body := bytes.NewBuffer([]byte{})

	if input != nil {
		if data, err := json.Marshal(input); err == nil {
			body = bytes.NewBuffer(data)
		} else {
			l.Error("error marshaling the request body to JSON", zap.Error(err))
			return nil, err
		}
	}

	accessToken, err := s.getAccessToken(ctx)

	if err != nil {
		l.Error("error getting accessToken", zap.Error(err))
		return nil, err
	}

	req, err := http.NewRequest(method, s.urlFor(ctx, resource, path), body)

	if err != nil {
		l.Error(
			"error creating request",
			zap.String("method", method),
			zap.String("resource", resource),
			zap.String("path", path),
			zap.Error(err),
		)
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)

	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		req.Header.Set("Content-Type", "application/json")
	}

	l.Debug("calling API", zap.String("method", method), zap.String("url", req.URL.String()))

	data, statusCode, err := handleResponse(s.httpClient.Do(req))

	// Check for unauthorized or access denied
	if statusCode.StatusCode == http.StatusUnauthorized || statusCode.StatusCode == http.StatusForbidden {
		s.clearTokenCache(ctx)
		l.Error("token cache cleared due to unauthorized or access denied response")
	}

	return data, err
}

// searchResources uses the accessToken to search for API resources.
// It assumes an appropriate combination of resource, search text.
// field is optional
func (s *Server) searchResources(ctx context.Context, resource, searchText, field string) ([]byte, error) {
	l := ctxzap.Extract(ctx)

	switch resource {
	case "secrets":
	default:
		message := "unknown resource"
		l.Error("error searching resources", zap.String("message", message), zap.String("resource", resource))
		return nil, fmt.Errorf(message)
	}

	method := "GET"
	body := bytes.NewBuffer([]byte{})

	accessToken, err := s.getAccessToken(ctx)

	if err != nil {
		l.Error("error getting accessToken", zap.Error(err))
		return nil, err
	}

	req, err := http.NewRequest(method, s.urlForSearch(ctx, resource, searchText, field), body)

	if err != nil {
		l.Error(
			"error creating search request",
			zap.String("method", method),
			zap.String("resource", resource),
			zap.String("searchText", searchText),
			zap.String("field", field),
			zap.Error(err),
		)
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)

	l.Debug("calling API", zap.String("method", method), zap.String("url", req.URL.String()))

	data, _, err := handleResponse(s.httpClient.Do(req))

	return data, err
}

// uploadFile uploads the file described in the given fileField to the
// secret at the given secretId as a multipart/form-data request.
func (s *Server) uploadFile(ctx context.Context, secretId int, fileField SecretField) error {
	l := ctxzap.Extract(ctx)

	l.Debug("uploading a file to the field", zap.String("slug", fileField.Slug), zap.String("filename", fileField.Filename))
	body := bytes.NewBuffer([]byte{})
	uploadPath := path.Join(strconv.Itoa(secretId), "fields", fileField.Slug)

	// Fetch the access token
	accessToken, err := s.getAccessToken(ctx)
	if err != nil {
		l.Error("error getting accessToken", zap.Error(err))
		return err
	}

	// Create the multipart form
	multipartWriter := multipart.NewWriter(body)
	filename := fileField.Filename
	if filename == "" {
		filename = "File.txt"
		l.Debug("field has no filename, setting its filename", zap.String("filename", filename))
	} else if match, _ := regexp.Match("[^.]+\\.\\w+$", []byte(filename)); !match {
		filename = filename + ".txt"
		l.Debug("field has no filename extension, setting its filename", zap.String("filename", filename))
	}
	form, err := multipartWriter.CreateFormFile("file", filename)
	if err != nil {
		return err
	}
	_, err = io.Copy(form, strings.NewReader(fileField.ItemValue))
	if err != nil {
		return err
	}
	err = multipartWriter.Close()
	if err != nil {
		return err
	}

	// Make the request
	req, err := http.NewRequest(http.MethodPut, s.urlFor(ctx, resource, uploadPath), body)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", multipartWriter.FormDataContentType())

	l.Debug("uploading file with PUT", zap.String("url", req.URL.String()))
	_, _, err = handleResponse(s.httpClient.Do(req))
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) setCacheAccessToken(ctx context.Context, value string, expiresIn int, baseURL string) error {
	cache := TokenCache{}
	cache.AccessToken = value
	cache.ExpiresIn = (int(time.Now().Unix()) + expiresIn) - int(math.Floor(float64(expiresIn)*0.9))

	data, _ := json.Marshal(cache)
	os.Setenv("SS_AT_"+url.QueryEscape(baseURL), string(data))
	return nil
}

func (s *Server) getCacheAccessToken(ctx context.Context, baseURL string) (string, bool) {
	data, ok := os.LookupEnv("SS_AT_" + url.QueryEscape(baseURL))
	if !ok {
		s.clearTokenCache(ctx)
		return "", ok
	}
	cache := TokenCache{}
	if err := json.Unmarshal([]byte(data), &cache); err != nil {
		return "", false
	}
	if time.Now().Unix() < int64(cache.ExpiresIn) {
		return cache.AccessToken, true
	}
	return "", false
}

func (s *Server) clearTokenCache(ctx context.Context) {
	var baseURL string

	if s.ServerURL == "" {
		baseURL = fmt.Sprintf(cloudBaseURLTemplate, s.Tenant, s.TLD)
	} else {
		baseURL = s.ServerURL
	}

	os.Setenv("SS_AT_"+url.QueryEscape(baseURL), "")
}

// getAccessToken gets an OAuth2 Access Grant and returns the token
// endpoint and get an accessGrant.
func (s *Server) getAccessToken(ctx context.Context) (string, error) {
	l := ctxzap.Extract(ctx)
	if s.Credentials.Token != "" {
		return s.Credentials.Token, nil
	}
	var baseURL string

	if s.ServerURL == "" {
		baseURL = fmt.Sprintf(cloudBaseURLTemplate, s.Tenant, s.TLD)
	} else {
		baseURL = s.ServerURL
	}

	response, err := s.checkPlatformDetails(ctx, baseURL)
	if err != nil {
		l.Error("Error while checking platform details:", zap.Error(err))
		return "", err
	} else if err == nil && response == "" {

		accessToken, found := s.getCacheAccessToken(ctx, baseURL)
		if found {
			return accessToken, nil
		}

		values := url.Values{
			"username":   {s.Credentials.Username},
			"password":   {s.Credentials.Password},
			"grant_type": {"password"},
		}
		if s.Credentials.Domain != "" {
			values["domain"] = []string{s.Credentials.Domain}
		}

		body := strings.NewReader(values.Encode())
		requestUrl := s.urlFor(ctx, "token", "")
		data, _, err := handleResponse(http.Post(requestUrl, "application/x-www-form-urlencoded", body))

		if err != nil {
			l.Error("Error while getting token response:", zap.Error(err))
			return "", err
		}

		grant := struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			TokenType    string `json:"token_type"`
			ExpiresIn    int    `json:"expires_in"`
		}{}

		if err = json.Unmarshal(data, &grant); err != nil {
			l.Error("error parsing grant response", zap.Error(err))
			return "", err
		}
		if err = s.setCacheAccessToken(ctx, grant.AccessToken, grant.ExpiresIn, baseURL); err != nil {
			l.Error("error caching access token", zap.Error(err))
			return "", err
		}
		return grant.AccessToken, nil
	} else {
		return response, nil
	}
}

func (s *Server) checkPlatformDetails(ctx context.Context, baseURL string) (string, error) {
	l := ctxzap.Extract(ctx)

	platformHelthCheckUrl := fmt.Sprintf("%s/%s", strings.Trim(baseURL, "/"), "health")
	ssHealthCheckUrl := fmt.Sprintf("%s/%s", strings.Trim(baseURL, "/"), "healthcheck.aspx")

	isHealthy := checkJSONResponse(ctx, ssHealthCheckUrl)
	if isHealthy {
		return "", nil
	} else {
		isHealthy := checkJSONResponse(ctx, platformHelthCheckUrl)
		if isHealthy {

			accessToken, found := s.getCacheAccessToken(ctx, baseURL)
			if !found {
				requestData := url.Values{}
				requestData.Set("grant_type", "client_credentials")
				requestData.Set("client_id", s.Credentials.Username)
				requestData.Set("client_secret", s.Credentials.Password)
				requestData.Set("scope", "xpmheadless")

				req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/%s", strings.Trim(baseURL, "/"), "identity/api/oauth2/token/xpmplatform"), bytes.NewBufferString(requestData.Encode()))
				if err != nil {
					l.Error("error creating HTTP request", zap.Error(err))
					return "", err
				}

				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				data, _, err := handleResponse((&http.Client{}).Do(req))
				if err != nil {
					l.Error("error while getting token response:", zap.Error(err))
					return "", err
				}

				var tokenjsonResponse OAuthTokens
				if err = json.Unmarshal(data, &tokenjsonResponse); err != nil {
					l.Error("error parsing get token response:", zap.Error(err))
					return "", err
				}
				accessToken = tokenjsonResponse.AccessToken

				if err = s.setCacheAccessToken(ctx, tokenjsonResponse.AccessToken, tokenjsonResponse.ExpiresIn, baseURL); err != nil {
					l.Error("error caching access token:", zap.Error(err))
					return "", err
				}
			}

			req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s", strings.Trim(baseURL, "/"), "vaultbroker/api/vaults"), bytes.NewBuffer([]byte{}))
			if err != nil {
				l.Error("error creating HTTP request:", zap.Error(err))
				return "", err
			}
			req.Header.Add("Authorization", "Bearer "+accessToken)

			data, _, err := handleResponse(s.httpClient.Do(req))
			if err != nil {
				l.Error("error while getting vaults response:", zap.Error(err))
				return "", err
			}

			var vaultJsonResponse VaultsResponseModel
			if err = json.Unmarshal(data, &vaultJsonResponse); err != nil {
				l.Error("error parsing vaults response:", zap.Error(err))
				return "", err
			}

			var vaultURL string
			for _, vault := range vaultJsonResponse.Vaults {
				if vault.IsDefault && vault.IsActive {
					vaultURL = vault.Connection.Url
					break
				}
			}
			if vaultURL != "" {
				s.ServerURL = vaultURL
			} else {
				return "", fmt.Errorf("no configured vault found")
			}

			return accessToken, nil
		}
	}
	return "", fmt.Errorf("invalid URL")
}

func checkJSONResponse(ctx context.Context, url string) bool {
	l := ctxzap.Extract(ctx)

	response, err := http.Get(url)
	if err != nil {
		l.Error("error making GET request", zap.Error(err))
		return false
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		l.Error("error reading response body", zap.Error(err))
		return false
	}

	var jsonResponse Response
	err = json.Unmarshal(body, &jsonResponse)
	if err == nil {
		return jsonResponse.Healthy
	} else {
		return strings.Contains(string(body), "Healthy")
	}
}

type Response struct {
	Healthy               bool `json:"healthy"`
	DatabaseHealthy       bool `json:"databaseHealthy"`
	ServiceBusHealthy     bool `json:"serviceBusHealthy"`
	StorageAccountHealthy bool `json:"storageAccountHealthy"`
	ScheduledForDeletion  bool `json:"scheduledForDeletion"`
}

type OAuthTokens struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	IdToken          string `json:"id_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	SessionExpiresIn int    `json:"session_expires_in"`
	Scope            string `json:"scope"`
}

type Connection struct {
	Url            string `json:"url"`
	OAuthProfileId string `json:"oAuthProfileId"`
}

type Vault struct {
	VaultId         string     `json:"vaultId"`
	Name            string     `json:"name"`
	Type            string     `json:"type"`
	IsDefault       bool       `json:"isDefault"`
	IsGlobalDefault bool       `json:"isGlobalDefault"`
	IsActive        bool       `json:"isActive"`
	Connection      Connection `json:"connection"`
}

type VaultsResponseModel struct {
	Vaults []Vault `json:"vaults"`
}
