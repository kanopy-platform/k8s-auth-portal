package server

import (
	"embed"
	"html/template"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/kanopy-platform/k8s-auth-portal/pkg/random"
	log "github.com/sirupsen/logrus"
)

//go:embed templates
var embeddedFS embed.FS

type Server struct {
	*mux.Router
	template      *template.Template
	cookies       *sessions.CookieStore
	sessionName   string
	sessionSecret string
}

func New(opts ...func(*Server)) (http.Handler, error) {
	sessionSecret, err := random.SecureString(32)
	if err != nil {
		return nil, err
	}

	s := &Server{
		Router:        mux.NewRouter(),
		template:      template.Must(template.ParseFS(embeddedFS, "templates/*.tmpl")),
		sessionName:   "k8s-auth-portal-session",
		sessionSecret: sessionSecret,
	}

	for _, opt := range opts {
		opt(s)
	}

	s.cookies = sessions.NewCookieStore([]byte(sessionSecret))
	s.routes()

	return s, nil
}

func (s *Server) routes() {
	s.HandleFunc("/", s.handleRoot())
	s.HandleFunc("/login", s.handleLogin()).Methods(http.MethodPost)
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
	}
}

func logAndError(w http.ResponseWriter, code int, err error, msg string) {
	log.WithError(err).Error(msg)
	http.Error(w, http.StatusText(code), code)
}
