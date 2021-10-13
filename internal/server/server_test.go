package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
)

var server *Server

type providerJSON struct {
	Issuer   string `json:"issuer"`
	AuthURL  string `json:"authorization_endpoint"`
	TokenURL string `json:"token_endpoint"`
}

type oidcProviderRoundTripper struct {
	statusCode int
	status     string
	bodyStr    string
}

func NewOidcProviderRoundTripper() *oidcProviderRoundTripper {
	return &oidcProviderRoundTripper{}
}

func (o *oidcProviderRoundTripper) WithProviderInfo() *oidcProviderRoundTripper {
	p := &providerJSON{
		Issuer:   "https://dex.example.com",
		AuthURL:  "https://dex.example.com/auth",
		TokenURL: "https://dex.example.com/token",
	}
	body, err := json.Marshal(p)
	if err != nil {
		log.Fatalf("error marshalling JSON: %v", err)
	}

	o.statusCode = 200
	o.bodyStr = string(body)
	return o
}

func (o *oidcProviderRoundTripper) WithServiceUnavailable() *oidcProviderRoundTripper {
	o.statusCode = 503
	o.status = "503 Service Unavailable"
	return o
}

func (o *oidcProviderRoundTripper) WithResponseHealthCheckPassed() *oidcProviderRoundTripper {
	o.statusCode = 200
	o.status = "200 OK"
	o.bodyStr = "Health check passed"
	return o
}

func (o *oidcProviderRoundTripper) WithResponseIssueWithDex() *oidcProviderRoundTripper {
	o.statusCode = 200
	o.status = "200 OK"
	o.bodyStr = "issue with dex"
	return o
}

func (o *oidcProviderRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	resp := &http.Response{
		StatusCode: o.statusCode,
		Status:     o.status,
		Body:       io.NopCloser(strings.NewReader(string(o.bodyStr))),
	}

	return resp, nil
}

func TestMain(m *testing.M) {
	var err error

	client := &http.Client{
		Transport: NewOidcProviderRoundTripper().WithProviderInfo(),
	}

	server, err = New(
		WithHTTPClient(client),
	)
	if err != nil {
		log.Printf("server.New failed, error: %v", err)
		os.Exit(1)
	}

	server.oauth2Config = &mockOauth2Config{}
	server.verifier = oidc.NewVerifier("", &mockKeySet{}, &oidc.Config{ClientID: server.kubectlClientID})

	os.Exit(m.Run())
}

func TestHandleRoot(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	server.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleLoginGet(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	server.ServeHTTP(w, httptest.NewRequest("GET", "/login", nil))
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleLoginPost(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	server.ServeHTTP(w, httptest.NewRequest("POST", "/login", nil))
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.NotEmpty(t, w.Result().Cookies()[0])
}

func TestHandleCallbackGet(t *testing.T) {
	t.Parallel()

	const validCallbackUrl = "/callback?code=testcode"
	testNonce = "test-nonce-123"

	tests := []struct {
		url            string
		nonce          string
		wantHttpStatus int
	}{
		{
			// success case
			url:            validCallbackUrl,
			nonce:          testNonce,
			wantHttpStatus: http.StatusOK,
		},
		{
			// error in request URL
			url:            "/callback?code=testcode&error=some-error",
			nonce:          testNonce,
			wantHttpStatus: http.StatusBadRequest,
		},
		{
			// no authorization code
			url:            "/callback",
			nonce:          testNonce,
			wantHttpStatus: http.StatusUnauthorized,
		},
		{
			// empty authorization code
			url:            "/callback?code=",
			nonce:          testNonce,
			wantHttpStatus: http.StatusUnauthorized,
		},
		{
			// nonce doesn't match expected
			url:            validCallbackUrl,
			nonce:          "invalid nonce",
			wantHttpStatus: http.StatusUnauthorized,
		},
	}

	for _, test := range tests {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", test.url, nil)

		session := server.getSession(req)
		session.Values["nonce"] = test.nonce

		server.ServeHTTP(rr, req)
		assert.Equal(t, test.wantHttpStatus, rr.Code)
	}
}

func TestHandleHealthCheckGet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		client           *http.Client
		wantHealthStatus string
		wantHttpStatus   int
	}{
		{
			// success case
			client:           &http.Client{Transport: NewOidcProviderRoundTripper().WithResponseHealthCheckPassed()},
			wantHealthStatus: "ok",
			wantHttpStatus:   http.StatusOK,
		},
		{
			// oidc provider returns error in HTTP status code
			client:           &http.Client{Transport: NewOidcProviderRoundTripper().WithServiceUnavailable()},
			wantHealthStatus: fmt.Sprintf("oidc provider %v returned HTTP 503 Service Unavailable", server.issuerURL),
			wantHttpStatus:   http.StatusBadGateway,
		},
		{
			// oidc provider returns error in body
			client:           &http.Client{Transport: NewOidcProviderRoundTripper().WithResponseIssueWithDex()},
			wantHealthStatus: fmt.Sprintf("oidc provider %v returned unexpected health check body", server.issuerURL),
			wantHttpStatus:   http.StatusBadGateway,
		},
	}

	for _, test := range tests {
		server.client = test.client
		response := &healthCheckResponse{}

		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/healthz", nil)
		server.ServeHTTP(rr, req)
		assert.Equal(t, test.wantHttpStatus, rr.Code)

		err := json.Unmarshal(rr.Body.Bytes(), response)
		assert.NoError(t, err)
		assert.Equal(t, test.wantHealthStatus, response.Status)
	}
}
