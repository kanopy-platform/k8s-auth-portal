package server

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"net/url"

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
	template      *template.Template
	cookies       *sessions.CookieStore
	sessionName   string
	sessionSecret string
	apiServerURL  *url.URL
	clusterCA     string
	issuerURL     *url.URL
	oauth2Config  *oauth2.Config
}

type ServerFuncOpt func(*Server) error

func New(opts ...ServerFuncOpt) (http.Handler, error) {

	// set defaults
	s := &Server{
		Router:        mux.NewRouter(),
		template:      template.Must(template.ParseFS(embeddedFS, "templates/*.tmpl")),
		sessionName:   "k8s-auth-portal-session",
		sessionSecret: "",
		oauth2Config: &oauth2.Config{
			ClientID:     "kubectl",
			ClientSecret: "replace_this_public_client_secret",
			RedirectURL:  "urn:ietf:wg:oauth:2.0:oob", // special "out-of-browser" redirect https://github.com/coreos/dex/blob/master/Documentation/custom-scopes-claims-clients.md#public-clients
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "offline_access", "groups"},
		},
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
	s.routes()

	return s, nil
}

func (s *Server) routes() {
	s.HandleFunc("/", s.handleRoot())
	s.HandleFunc("/login", s.handleLogin()).Methods(http.MethodPost)
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

		rs, err := random.SecureString(32)
		if err != nil {
			logAndError(w, http.StatusInternalServerError, err, "error generating random string")
			return
		}

		session.Values["rand"] = rs

		if err := session.Save(r, w); err != nil {
			logAndError(w, http.StatusInternalServerError, err, "error saving session")
			return
		}

		fmt.Fprintf(w, "session saved")
	}
}
