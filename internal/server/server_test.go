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

type oidcProviderRoundTripper struct{}

func (o *oidcProviderRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	resp := &http.Response{
		StatusCode: 200,
	}

	p := &providerJSON{
		Issuer:   "https://dex.example.com",
		AuthURL:  "https://dex.example.com/auth",
		TokenURL: "https://dex.example.com/token",
	}

	body, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	resp.Body = io.NopCloser(strings.NewReader(string(body)))

	return resp, nil
}

func TestMain(m *testing.M) {
	var err error

	client := &http.Client{
		Transport: &oidcProviderRoundTripper{},
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

	tests := []struct {
		body           string
		wantHttpStatus int
	}{
		{
			// empty POST form
			body:           "",
			wantHttpStatus: http.StatusBadRequest,
		},
		{
			// empty state
			body:           "state=",
			wantHttpStatus: http.StatusBadRequest,
		},
		{
			// valid state
			body:           "state=test-123",
			wantHttpStatus: http.StatusSeeOther,
		},
	}

	for _, test := range tests {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/login", strings.NewReader(test.body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		server.ServeHTTP(rr, req)
		assert.Equal(t, test.wantHttpStatus, rr.Code)

		if test.wantHttpStatus == http.StatusSeeOther {
			assert.NotEmpty(t, rr.Result().Cookies()[0])
		}
	}
}

func TestHandleCallbackGet(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	server.ServeHTTP(w, httptest.NewRequest("GET", "/callback", nil))
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleCallbackPost(t *testing.T) {
	t.Parallel()

	const (
		validCallbackUrl = "/callback"
		sessionState     = "test-state-123"
		validAuthCode    = "test-code-123"
	)
	testNonce = "test-nonce-123"

	tests := []struct {
		url            string
		body           string
		nonce          string
		wantHttpStatus int
	}{
		{
			// success case
			url:            validCallbackUrl,
			body:           fmt.Sprintf("state=%s&code=%s", sessionState, validAuthCode),
			nonce:          testNonce,
			wantHttpStatus: http.StatusOK,
		},
		{
			// error in request URL
			url:            "/callback?code=testcode&error=some-error",
			body:           fmt.Sprintf("state=%s&code=%s", sessionState, validAuthCode),
			nonce:          testNonce,
			wantHttpStatus: http.StatusBadRequest,
		},
		{
			// no state
			url:            validCallbackUrl,
			body:           fmt.Sprintf("code=%s", validAuthCode),
			nonce:          testNonce,
			wantHttpStatus: http.StatusBadRequest,
		},
		{
			// empty state
			url:            validCallbackUrl,
			body:           fmt.Sprintf("state=&code=%s", validAuthCode),
			nonce:          testNonce,
			wantHttpStatus: http.StatusBadRequest,
		},
		{
			// POST and session state does not match
			url:            validCallbackUrl,
			body:           fmt.Sprintf("state=%s&code=%s", "mismatched-state", validAuthCode),
			nonce:          testNonce,
			wantHttpStatus: http.StatusBadRequest,
		},
		{
			// no authorization code
			url:            validCallbackUrl,
			body:           fmt.Sprintf("state=%s", sessionState),
			nonce:          testNonce,
			wantHttpStatus: http.StatusUnauthorized,
		},
		{
			// empty authorization code
			url:            validCallbackUrl,
			body:           fmt.Sprintf("state=%s&code=", sessionState),
			nonce:          testNonce,
			wantHttpStatus: http.StatusUnauthorized,
		},
		{
			// nonce doesn't match expected
			url:            validCallbackUrl,
			body:           fmt.Sprintf("state=%s&code=%s", sessionState, validAuthCode),
			nonce:          "mismatched-nonce",
			wantHttpStatus: http.StatusUnauthorized,
		},
	}

	for _, test := range tests {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("POST", test.url, strings.NewReader(test.body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		session := server.getSession(req)
		session.Values["state"] = sessionState
		session.Values["nonce"] = test.nonce

		server.ServeHTTP(rr, req)
		assert.Equal(t, test.wantHttpStatus, rr.Code)
	}
}
