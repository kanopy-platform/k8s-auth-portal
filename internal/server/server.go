package server

import (
	"embed"
	"html/template"
	"net/http"

	log "github.com/sirupsen/logrus"
)

//go:embed templates
var embeddedFS embed.FS

type Server struct {
	router   *http.ServeMux
	template *template.Template
}

func New() http.Handler {
	s := &Server{
		router:   http.NewServeMux(),
		template: template.Must(template.ParseFS(embeddedFS, "templates/*.tmpl")),
	}

	s.router.HandleFunc("/", s.handleRoot())

	return s.router
}

func (s *Server) handleRoot() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := s.template.ExecuteTemplate(w, "view_index.tmpl", nil); err != nil {
			log.WithError(err).Error("error executing template")
			httpError(w, http.StatusInternalServerError)
			return
		}
	}
}

func httpError(w http.ResponseWriter, code int) {
	http.Error(w, http.StatusText(code), code)
}
