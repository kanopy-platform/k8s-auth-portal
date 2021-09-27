package server

import (
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/assert"
)

var server *Server

func TestMain(m *testing.M) {
	var err error
	server, err = New(
		WithClusterCA("testdata/test.crt"),
	)
	if err != nil {
		log.Printf("server.New failed, error: %v", err)
		os.Exit(1)
	}

	// must override Provider before calling ConfigureOpenID
	server.oidcProvider = &MockOIDCClient{}

	if err = server.ConfigureOpenID(); err != nil {
		log.Printf("server.ConfigureOpenID failed, error: %v", err)
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
