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
	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/assert"
)

var server *Server

type providerJSON struct {
	Issuer   string `json:"issuer"`
	AuthURL  string `json:"authorization_endpoint"`
	TokenURL string `json:"token_endpoint"`
}

type OIDCProviderRoundTripper struct{}

func (o *OIDCProviderRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	fmt.Println(r)

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
		Transport: &OIDCProviderRoundTripper{},
	}

	server, err = New(
		WithHTTPClient(client),
	)
	if err != nil {
		log.Printf("server.New failed, error: %v", err)
		os.Exit(1)
	}

	server.oauth2Config = &MockOauth2Config{}
	server.verifier = oidc.NewVerifier("", &MockKeySet{}, &oidc.Config{ClientID: server.kubectlClientID})

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

	var (
		w       *httptest.ResponseRecorder
		req     *http.Request
		session *sessions.Session
	)

	const validCallbackUrl = "/callback?code=testcode"

	// Success path
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", validCallbackUrl, nil)
	session = server.getSession(req)
	session.Values["nonce"] = ""
	server.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Error in request URL
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/callback?code=testcode&error=some-error", nil)
	server.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Empty authorization code
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", validCallbackUrl, nil)
	server.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Nonce doesn't match
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", validCallbackUrl, nil)
	session = server.getSession(req)
	session.Values["nonce"] = "invalid nonce"
	server.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
