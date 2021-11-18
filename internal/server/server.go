package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/kanopy-platform/k8s-auth-portal/pkg/random"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

//go:embed templates
var embeddedFS embed.FS

type oauth2ConfigProvider interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
}

type oidcIDTokenVerifier interface {
	Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)
}

type Server struct {
	*mux.Router
	template            *template.Template
	cookies             *sessions.CookieStore
	reponseHeaders      map[string]string
	sessionName         string
	sessionSecret       string
	apiServerURL        *url.URL
	clusterCA           string
	issuerURL           *url.URL
	kubectlClientID     string
	kubectlClientSecret string
	scopes              []string
	oauth2Config        oauth2ConfigProvider
	client              *http.Client // OIDC client to support custom root CA certificates
	verifier            oidcIDTokenVerifier
	debugURL            *url.URL // TODO remove this once /healthz hang issue is resolved
}

type healthCheckResponse struct {
	Status string `json:"status"`
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
	s.cookies.Options.Secure = true
	s.cookies.Options.HttpOnly = true
	s.cookies.Options.SameSite = http.SameSiteStrictMode

	if err := s.ConfigureOpenID(); err != nil {
		return nil, err
	}
	s.configureResponseHeaders()
	s.routes()

	return s, nil
}

func (s *Server) initHttpClient() error {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableKeepAlives = true // This may prevent occasional http.Client lockups

	if s.clusterCA != "" {
		// decode root certificates
		rootCABytes, err := base64.StdEncoding.DecodeString(s.clusterCA)
		if err != nil {
			return err
		}

		tlsConfig := tls.Config{RootCAs: x509.NewCertPool()}
		if !tlsConfig.RootCAs.AppendCertsFromPEM(rootCABytes) {
			return fmt.Errorf("no certs found in rootCABase64")
		}

		transport.TLSClientConfig = &tlsConfig
	}

	s.client = &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	return nil
}

func (s *Server) ConfigureOpenID() error {
	// if the client has not been overridden with a mock client
	if s.client == nil {
		if err := s.initHttpClient(); err != nil {
			return err
		}
	}

	oidcContext := oidc.ClientContext(context.Background(), s.client)
	provider, err := oidc.NewProvider(oidcContext, s.issuerURL.String())
	if err != nil {
		return err
	}

	s.verifier = provider.Verifier(&oidc.Config{ClientID: s.kubectlClientID})
	s.oauth2Config = &oauth2.Config{
		ClientID:     s.kubectlClientID,
		ClientSecret: s.kubectlClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "urn:ietf:wg:oauth:2.0:oob", // special "out-of-browser" redirect https://dexidp.io/docs/custom-scopes-claims-clients/#public-clients
		Scopes:       s.scopes,
	}

	return nil
}

func (s *Server) configureResponseHeaders() {
	s.reponseHeaders = make(map[string]string)

	// The following headers are added for security

	// Prevent click-jacking. Note this is obselete for newer browsers
	// that support: Content-Security-Policy frame-ancestors 'none'
	s.reponseHeaders["X-Frame-Options"] = "DENY"

	// Prevent XSS attacks and click-jacking
	s.reponseHeaders["Content-Security-Policy"] = "default-src 'self';" + // by default all content (css, script, img, etc) must come from our URL:port
		"style-src https://maxcdn.bootstrapcdn.com;" + // .css exceptions
		"script-src https://code.jquery.com https://cdnjs.cloudflare.com https://maxcdn.bootstrapcdn.com;" + // .js exceptions
		"frame-ancestors 'none';" // page cannot be embedded in frame, similar to X-Frame-Options: DENY
}

func (s *Server) commonHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for header, value := range s.reponseHeaders {
			w.Header().Set(header, value)
		}

		next.ServeHTTP(w, r)
	})
}

func logAndError(w http.ResponseWriter, code int, err error, msg string) {
	log.WithError(err).Error(msg)
	http.Error(w, http.StatusText(code), code)
}

func writeJsonResponse(w http.ResponseWriter, httpResponse int, data interface{}) {
	jsonResp, err := json.Marshal(data)
	if err != nil {
		logAndError(w, http.StatusInternalServerError, err, "error marshaling json")
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(httpResponse) // keep this after w.Header().Set() to keep "Content-Type": "application/json"
	if _, err := w.Write(jsonResp); err != nil {
		logAndError(w, http.StatusInternalServerError, err, "failed to write JSON response")
		return
	}
}

func (s *Server) getSession(r *http.Request) *sessions.Session {
	session, err := s.cookies.Get(r, s.sessionName)
	if err != nil {
		// warn about error but continue to return new session
		log.WithError(err).Warn("error getting sesssion")
	}

	return session
}

func (s *Server) getIssuerIP() []net.IP {
	addrs, err := net.LookupIP(s.issuerURL.Host)
	if err != nil {
		// log error but continue
		log.WithError(err).Errorf("error looking up IPs for %v", s.issuerURL.Host)
	}

	return addrs
}

// TODO remove once http client hangup debug done
func (s *Server) clientGetWithHttpTrace(url string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	clientTrace := &httptrace.ClientTrace{
		// the order of HTTP lifecycle is same as listed order below
		GetConn:      func(hostPort string) { log.Info(fmt.Sprintf("starting to create conn %v", hostPort)) },
		DNSStart:     func(info httptrace.DNSStartInfo) { log.Info(fmt.Sprintf("starting to look up dns %v", info)) },
		DNSDone:      func(info httptrace.DNSDoneInfo) { log.Info(fmt.Sprintf("done looking up dns %v", info)) },
		ConnectStart: func(network, addr string) { log.Info(fmt.Sprintf("starting tcp connection %v %v", network, addr)) },
		ConnectDone: func(network, addr string, err error) {
			log.Info(fmt.Sprintf("tcp connection created %v %v %v", network, addr, err))
		},
		TLSHandshakeStart:    func() { log.Info("TLS Handshake started") },
		TLSHandshakeDone:     func(cs tls.ConnectionState, e error) { log.Info("TLS Handshank done") },
		GotConn:              func(info httptrace.GotConnInfo) { log.Info(fmt.Sprintf("connection established %v", info)) },
		WroteHeaders:         func() { log.Info("wrote all request headers") },
		WroteRequest:         func(info httptrace.WroteRequestInfo) { log.Info(fmt.Sprintf("wrote request %v", info)) },
		GotFirstResponseByte: func() { log.Info("got first response byte") },
		// below are not expected to be called, but included just in case
		PutIdleConn:    func(err error) { log.Info(fmt.Sprintf("putting connection back in idle pool, err %v", err)) },
		Got100Continue: func() { log.Info("got 100 Continue response") },
	}
	clientTraceCtx := httptrace.WithClientTrace(req.Context(), clientTrace)
	req = req.WithContext(clientTraceCtx)
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	return nil
}

func (s *Server) routes() {
	s.Use(s.commonHeadersMiddleware)

	s.HandleFunc("/", s.handleRoot())
	s.HandleFunc("/login", s.handleLogin()).Methods(http.MethodPost)
	s.HandleFunc("/callback", s.handleCallback()).Methods(http.MethodPost)
	s.HandleFunc("/healthz", s.handleHealthCheck()).Methods(http.MethodGet)
	s.Handle("/metrics", promhttp.Handler())
}

func (s *Server) handleRoot() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err := random.SecureString(32)
		if err != nil {
			logAndError(w, http.StatusInternalServerError, err, "error generating random string for state")
			return
		}

		data := map[string]interface{}{
			"State": state,
		}

		if err := s.template.ExecuteTemplate(w, "view_index.tmpl", data); err != nil {
			logAndError(w, http.StatusInternalServerError, err, "error executing template")
			return
		}
	}
}

func (s *Server) handleLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			logAndError(w, http.StatusInternalServerError, err, "error parsing form")
			return
		}

		session := s.getSession(r)

		// CSRF attack prevention:
		// In normal OIDC flow, login -> redirect -> callback, a state would be passed into
		// the AuthCodeURL and saved in the session. After redirect, the callback handler would
		// check that the state in the URL matches the state stored in the session.
		//
		// However, our app's RedirectURL is out-of-band and does not redirect to the callback
		// handler. So there is no way to do "state" validation using the URL.
		//
		// Instead we generate and store a random state string as a hidden form field in index.html.
		// Pass it into /login, which saves it in the session cookie.
		// The /callback handler will verify the passed in state matches that from the session.
		// This achieves the equivalent functionality as using "state" in URL.
		randomStr, err := random.SecureString(32)
		if err != nil {
			logAndError(w, http.StatusInternalServerError, err, "error generating random string")
			return
		}

		state := r.PostFormValue("state")
		if state == "" {
			logAndError(w, http.StatusBadRequest, fmt.Errorf("state empty or does not exist"), "invalid state")
			return
		}
		session.Values["state"] = state

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
		if err := r.ParseForm(); err != nil {
			logAndError(w, http.StatusInternalServerError, err, "error parsing form")
			return
		}

		// handle requests that contain an error
		if err := r.URL.Query().Get("error"); err != "" {
			logAndError(w, http.StatusBadRequest, fmt.Errorf(err+": "+r.URL.Query().Get("error_description")), "error in request")
			return
		}

		session := s.getSession(r)
		oidcContext := oidc.ClientContext(r.Context(), s.client)

		state := r.PostFormValue("state")
		if state == "" || state != session.Values["state"] {
			logAndError(w, http.StatusBadRequest, fmt.Errorf("POST form and session state values do not match"), "invalid state")
			return
		}

		code := r.PostFormValue("code")
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

		log.WithFields(log.Fields{
			"email":           claims.Email,
			"x-forwarded-for": r.Header.Get("x-forwarded-for"),
		}).Info("kubeconfig generated")

		if err := s.template.ExecuteTemplate(w, "view_callback.tmpl", data); err != nil {
			logAndError(w, http.StatusInternalServerError, err, "error executing template")
			return
		}
	}
}

func (s *Server) handleHealthCheck() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const errPrefix = "/healthz: "

		var oidcResp *http.Response
		var err error

		oidcResp, err = s.client.Get(s.issuerURL.String() + "/healthz")
		if err != nil {
			status := fmt.Sprintf("cannot connect to %v", s.issuerURL)
			log.WithFields(log.Fields{
				"issuerURL":  s.issuerURL,
				"issuer IPs": s.getIssuerIP(),
				"err":        err,
			}).Error(errPrefix + status)

			// Code below is for debugging the /healthz hanging issue
			// Once issue is resolved, this block can be deleted
			// Debug Start

			// call GET with http-tracing
			log.Info(errPrefix + "retrying with http-tracing...")
			if err = s.clientGetWithHttpTrace(s.issuerURL.String() + "/healthz"); err != nil {
				log.Error(errPrefix + fmt.Sprintf("s.clientGetWithHttpTrace failed: %v", err))
			}

			// try another service instead of OIDC provider
			log.Info(errPrefix + "retrying with a different service...")
			resp, err := s.client.Get(s.debugURL.String())
			if err == nil {
				log.Info(errPrefix + fmt.Sprintf("s.client.Get worked for: %v", s.debugURL))
				resp.Body.Close()
			} else {
				log.Info(errPrefix + fmt.Sprintf("s.client.Get also failed for: %v", s.debugURL))
			}

			// retry with a new HTTP Client
			log.Info(errPrefix + "replacing server's shared http.Client...")
			if err := s.initHttpClient(); err != nil {
				log.Error(errPrefix + fmt.Sprintf("s.initHttpClient() failed: %v", err))
			}

			oidcResp, err = s.client.Get(s.issuerURL.String() + "/healthz")
			if err == nil {
				log.Info(errPrefix + fmt.Sprintf("on retry with new http.Client, can connect to %v", s.issuerURL))
			} else {
				log.WithFields(log.Fields{
					"issuerURL":  s.issuerURL,
					"issuer IPs": s.getIssuerIP(),
					"err":        err,
				}).Error(errPrefix + fmt.Sprintf("on retry with new http.Client, cannot connect to %v", s.issuerURL))

				writeJsonResponse(w, http.StatusBadGateway, healthCheckResponse{Status: status})
				return
			}

			// Debug End
			// TODO uncomment below
			// writeJsonResponse(w, http.StatusBadGateway, healthCheckResponse{Status: status})
			// return
		}
		defer oidcResp.Body.Close()

		bodyBytes, err := ioutil.ReadAll(oidcResp.Body)
		if err != nil {
			status := fmt.Sprintf("cannot read response body from %v", s.issuerURL)
			log.WithFields(log.Fields{
				"issuerURL":   s.issuerURL,
				"issuer IPs":  s.getIssuerIP(),
				"err":         err,
				"HTTP status": oidcResp.Status,
			}).Error(errPrefix + status)

			writeJsonResponse(w, http.StatusBadGateway, healthCheckResponse{Status: status})
			return
		}
		bodyString := string(bodyBytes)

		if oidcResp.StatusCode > 299 {
			status := fmt.Sprintf("oidc provider %v returned HTTP %v", s.issuerURL, oidcResp.Status)
			log.WithFields(log.Fields{
				"issuerURL":             s.issuerURL,
				"issuer IPs":            s.getIssuerIP(),
				"oidc healthz response": bodyString,
			}).Error(errPrefix + status)

			writeJsonResponse(w, http.StatusBadGateway, healthCheckResponse{Status: status})
			return
		}

		if bodyString != "Health check passed" {
			status := fmt.Sprintf("oidc provider %v returned unexpected health check body", s.issuerURL)
			log.WithFields(log.Fields{
				"issuerURL":             s.issuerURL,
				"issuer IPs":            s.getIssuerIP(),
				"HTTP status":           oidcResp.Status,
				"oidc healthz response": bodyString,
			}).Error(errPrefix + status)

			writeJsonResponse(w, http.StatusBadGateway, healthCheckResponse{Status: status})
			return
		}

		writeJsonResponse(w, http.StatusOK, healthCheckResponse{Status: "ok"})
	}
}
