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
	router *http.ServeMux
	tmpl   *template.Template
}

func New() http.Handler {
	s := &Server{
		router: http.NewServeMux(),
		tmpl:   template.Must(template.ParseFS(embeddedFS, "templates/*.tmpl")),
	}

	s.router.HandleFunc("/", s.handleRoot())

	return s.router
}

func (s *Server) handleRoot() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := s.tmpl.ExecuteTemplate(w, "view_index.tmpl", nil); err != nil {
			log.WithError(err).Error("error executing template")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}
}
