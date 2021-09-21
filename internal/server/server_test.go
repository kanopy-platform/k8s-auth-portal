package server

import (
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/kanopy-platform/k8s-auth-portal/pkg/mocks"
	"github.com/stretchr/testify/assert"
)

var testHandler http.Handler
var server *Server

func TestMain(m *testing.M) {
	var err error
	testHandler, err = New(
		WithClusterCA("testdata/test.crt"),
	)
	if err != nil {
		log.Printf("server.New failed, error: %v", err)
		os.Exit(1)
	}

	server = testHandler.(*Server)

	// override external funcs/methods with mocks
	server.externalFuncs = &ExternalFuncs{
		oidcNewProvider:           mocks.MockOidcNewProvider,
		oauth2ConfigExchange:      mocks.MockOauth2ConfigExchange,
		oidcIDTokenVerifierVerify: mocks.MockOidcIDTokenVerifierVerify,
		oidcIDTokenClaims:         mocks.MockOidcIDTokenClaims,
	}

	err = server.ConfigureOpenID()
	if err != nil {
		log.Printf("server.ConfigureOpenID failed, error: %v", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func TestHandleRoot(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	testHandler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleLoginGet(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	testHandler.ServeHTTP(w, httptest.NewRequest("GET", "/login", nil))
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleLoginPost(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	testHandler.ServeHTTP(w, httptest.NewRequest("POST", "/login", nil))
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

	// Success path
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/callback", nil)
	session = server.getSession(req)
	session.Values["nonce"] = ""
	testHandler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Error in request URL
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/callback?error=some-error", nil)
	testHandler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Code to Token Exchange returns error
	prevExchangeMethod := server.externalFuncs.oauth2ConfigExchange
	server.externalFuncs.oauth2ConfigExchange = mocks.MockOauth2ConfigExchangeError
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/callback", nil)
	testHandler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	server.externalFuncs.oauth2ConfigExchange = prevExchangeMethod

	// ID Token Verify returns error
	prevVerifyMethod := server.externalFuncs.oidcIDTokenVerifierVerify
	server.externalFuncs.oidcIDTokenVerifierVerify = mocks.MockOidcIDTokenVerifierVerifyError
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/callback", nil)
	testHandler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	server.externalFuncs.oidcIDTokenVerifierVerify = prevVerifyMethod

	// Nonce doesn't match
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/callback", nil)
	session = server.getSession(req)
	session.Values["nonce"] = "invalid nonce"
	testHandler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// ID Token Claims returns error
	prevClaimsMethod := server.externalFuncs.oidcIDTokenClaims
	server.externalFuncs.oidcIDTokenClaims = mocks.MockOidcIDTokenClaimsError
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/callback", nil)
	session = server.getSession(req)
	session.Values["nonce"] = ""
	testHandler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	server.externalFuncs.oidcIDTokenClaims = prevClaimsMethod
}
