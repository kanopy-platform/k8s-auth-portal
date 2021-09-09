package server

import "net/url"

func WithSessionName(name string) ServerFuncOpt {
	return func(s *Server) error {
		if name != "" {
			s.sessionName = name
		}
		return nil
	}
}

func WithSessionSecret(secret string) ServerFuncOpt {
	return func(s *Server) error {
		if secret != "" {
			s.sessionSecret = secret
		}

		return nil
	}
}

func WithAPIServerURL(api string) ServerFuncOpt {
	return func(s *Server) error {
		if api != "" {
			u, err := url.Parse(api)
			if err != nil {
				return err
			}
			s.apiServerURL = u
		}
		return nil
	}
}

func WithKubectlClientID(clientID string) ServerFuncOpt {
	return func(s *Server) error {
		if clientID != "" {
			s.kubectlClientID = clientID
		}

		return nil
	}
}

func WithIssuerURL(issuer string) ServerFuncOpt {
	return func(s *Server) error {
		if issuer != "" {
			u, err := url.Parse(issuer)
			if err != nil {
				return err
			}
			s.issuerURL = u
		}

		return nil
	}
}

func WithExtraScopes(scopes string) ServerFuncOpt {
	return func(s *Server) error {
		if scopes != "" {
			s.extraScopes = scopes
		}

		return nil
	}
}
