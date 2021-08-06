package server

import (
	"fmt"
	"net/http"
)

type Server struct {
	router *http.ServeMux
}

func New() http.Handler {
	s := &Server{router: http.NewServeMux()}

	s.router.HandleFunc("/", s.handleRoot())

	return s.router
}

func (s *Server) handleRoot() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello world")
	}
}
