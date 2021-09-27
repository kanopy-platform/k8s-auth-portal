package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/kanopy-platform/k8s-auth-portal/pkg/random"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

//go:embed templates
var embeddedFS embed.FS

type Server struct {
	*mux.Router
	oidcNewProviderFunc OIDCNewProviderFunc
	template            *template.Template
	cookies             *sessions.CookieStore
	sessionName         string
	sessionSecret       string
	apiServerURL        *url.URL
	clusterCA           string
	issuerURL           *url.URL
	kubectlClientID     string
	kubectlClientSecret string
	scopes              []string
	oauth2Config        Oauth2ConfigProvider
	client              *http.Client // OIDC client to support custom root CA certificates
	verifier            OIDCIDTokenVerifier
}

type ServerFuncOpt func(*Server) error

func New(opts ...ServerFuncOpt) (*Server, error) {
	randSecret, err := random.SecureString(32)
	if err != nil {
		return nil, err
	}

	// set defaults
	s := &Server{
		Router:              mux.NewRouter(),
		oidcNewProviderFunc: oidc.NewProvider,
		template:            template.Must(template.ParseFS(embeddedFS, "templates/*.tmpl")),
		sessionName:         "k8s-auth-portal-session",
		sessionSecret:       randSecret,
		kubectlClientID:     "kubectl",
		kubectlClientSecret: randSecret,
		scopes:              []string{oidc.ScopeOpenID, "profile", "email", "offline_access", "groups"},
	}

	// default builders
	o := []ServerFuncOpt{
		WithAPIServerURL("https://api.example.com"),
		WithIssuerURL("https://dex.example.com"),
	}

	opts = append(o, opts...)

	// load options
	for _, opt := range opts {
		err := opt(s)
		if err != nil {
			return nil, err
		}
	}

	// configure server
	s.cookies = sessions.NewCookieStore([]byte(s.sessionSecret))
	if err := s.ConfigureOpenID(); err != nil {
		return nil, err
	}
	s.routes()

	return s, nil
}

func httpClientForRootCAs(rootCABytes []byte) (*http.Client, error) {
	tlsConfig := tls.Config{RootCAs: x509.NewCertPool()}
	if !tlsConfig.RootCAs.AppendCertsFromPEM(rootCABytes) {
		return nil, fmt.Errorf("no certs found in rootCABase64")
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tlsConfig,
			Proxy:           http.ProxyFromEnvironment,
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}, nil
}

func (s *Server) ConfigureOpenID() error {
	var err error

	if s.clusterCA != "" {
		// decode root certificates
		rootCABytes, err := base64.StdEncoding.DecodeString(s.clusterCA)
		if err != nil {
			return err
		}
		// get HTTP Client with custom root CAs
		s.client, err = httpClientForRootCAs(rootCABytes)
		if err != nil {
			return err
		}
	} else {
		s.client = &http.Client{
			Timeout: 10 * time.Second,
		}
	}

	oidcContext := oidc.ClientContext(context.Background(), s.client)
	provider, err := s.oidcNewProviderFunc(oidcContext, s.issuerURL.String())
	if err != nil {
		return err
	}

	s.verifier = provider.Verifier(&oidc.Config{ClientID: s.kubectlClientID})
	s.oauth2Config = &oauth2.Config{
		ClientID:     s.kubectlClientID,
		ClientSecret: s.kubectlClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "urn:ietf:wg:oauth:2.0:oob",
		Scopes:       s.scopes,
	}

	return nil
}

func (s *Server) routes() {
	s.HandleFunc("/", s.handleRoot())
	s.HandleFunc("/login", s.handleLogin()).Methods(http.MethodPost)
	s.HandleFunc("/callback", s.handleCallback()).Methods(http.MethodGet)
}

func logAndError(w http.ResponseWriter, code int, err error, msg string) {
	log.WithError(err).Error(msg)
	http.Error(w, http.StatusText(code), code)
}

func (s *Server) getSession(r *http.Request) *sessions.Session {
	session, err := s.cookies.Get(r, s.sessionName)
	if err != nil {
		// warn about error but continue to return new session
		log.WithError(err).Warn("error getting sesssion")
	}

	return session
}

func (s *Server) handleRoot() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := s.template.ExecuteTemplate(w, "view_index.tmpl", nil); err != nil {
			logAndError(w, http.StatusInternalServerError, err, "error executing template")
			return
		}
	}
}

func (s *Server) handleLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := s.getSession(r)

		// Normally this randomStr would be a state, and saved in session.Values["state"].
		// Then in handleCallback() check the state in URL matches the session.Values["state"].
		// However, our app does not do the full login -> redirect -> callback loop.
		// The user hits /login, copies code, goes back to root page, and hits /callback.
		// So there is no way to pass a state in the URL between the login and callback.
		randomStr, err := random.SecureString(32)
		if err != nil {
			logAndError(w, http.StatusInternalServerError, err, "error generating random string for state")
			return
		}

		// generate nonce
		nonce, err := random.SecureString(32)
		if err != nil {
			logAndError(w, http.StatusInternalServerError, err, "error generating random string for nonce")
			return
		}
		session.Values["nonce"] = nonce

		if err := session.Save(r, w); err != nil {
			logAndError(w, http.StatusInternalServerError, err, "error saving session")
			return
		}

		http.Redirect(w, r, s.oauth2Config.AuthCodeURL(randomStr, oidc.Nonce(nonce)), http.StatusSeeOther)
	}
}

func (s *Server) handleCallback() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// handle requests that contain an error
		if err := r.URL.Query().Get("error"); err != "" {
			logAndError(w, http.StatusBadRequest, fmt.Errorf(err+": "+r.URL.Query().Get("error_description")), "error in request")
			return
		}

		session := s.getSession(r)
		oidcContext := oidc.ClientContext(r.Context(), s.client)

		// handle requests without an authorization code
		code := r.URL.Query().Get("code")
		if code == "" {
			logAndError(w, http.StatusUnauthorized, fmt.Errorf("authorization code empty"), "error in authorization code")
			return
		}

		// convert authorization code into an OAuth2 token
		oauth2Token, err := s.oauth2Config.Exchange(oidcContext, code)
		if err != nil {
			logAndError(w, http.StatusUnauthorized, err, "error converting code to token")
			return
		}

		// extract the ID token from OAuth2 token
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			logAndError(w, http.StatusInternalServerError, fmt.Errorf("error extracting id_token"), "no id_token in token response")
			return
		}

		// verify the ID token
		idToken, err := s.verifier.Verify(oidcContext, rawIDToken)
		if err != nil {
			logAndError(w, http.StatusInternalServerError, err, "failed to verify id_token")
			return
		}

		// verify the OIDC nonce matches
		if idToken.Nonce != session.Values["nonce"] {
			logAndError(w, http.StatusUnauthorized, fmt.Errorf("error invalid nonce"), "id token nonce does not match session nonce")
			return
		}

		// extract custom claims
		var claims struct {
			Email string `json:"email"`
		}
		if err := idToken.Claims(&claims); err != nil {
			logAndError(w, http.StatusInternalServerError, err, "error extracting claims")
			return
		}

		data := map[string]interface{}{
			"IDToken":       rawIDToken,
			"User":          claims.Email + "_" + s.apiServerURL.Hostname(),
			"RefreshToken":  oauth2Token.RefreshToken,
			"APIURL":        s.apiServerURL.String(),
			"APIHostname":   s.apiServerURL.Hostname(),
			"ClusterCAData": s.clusterCA,
			"IssuerURL":     s.issuerURL.String(),
			"IssuerCAData":  s.clusterCA,
			"ClientID":      s.kubectlClientID,
			"ClientSecret":  s.kubectlClientSecret,
		}

		if err := s.template.ExecuteTemplate(w, "view_callback.tmpl", data); err != nil {
			logAndError(w, http.StatusInternalServerError, err, "error executing template")
			return
		}
	}
}
