package server

func WithSessionName(name string) func(*Server) {
	return func(s *Server) {
		if name != "" {
			s.sessionName = name
		}
	}
}

func WithSessionSecret(secret string) func(*Server) {
	return func(s *Server) {
		if secret != "" {
			s.sessionSecret = secret
		}
	}
}
