package server

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"os"
)

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
			u, err := url.ParseRequestURI(api)
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
			u, err := url.ParseRequestURI(issuer)
			if err != nil {
				return err
			}
			s.issuerURL = u
		}

		return nil
	}
}

func WithExtraScopes(extraScopes ...string) ServerFuncOpt {
	return func(s *Server) error {
		for _, es := range extraScopes {
			if es != "" {
				s.scopes = append(s.scopes, es)
			}
		}

		return nil
	}
}

func WithClusterCA(filePath string) ServerFuncOpt {
	return func(s *Server) error {
		if filePath != "" {
			data, err := os.ReadFile(filePath)
			if err != nil {
				return err
			}

			s.clusterCA = base64.StdEncoding.EncodeToString([]byte(data))
		}

		return nil
	}
}

func WithKubectlClientSecret(secret string) ServerFuncOpt {
	return func(s *Server) error {
		if secret != "" {
			s.kubectlClientSecret = secret
		}

		return nil
	}
}

func WithHTTPClient(c *http.Client) ServerFuncOpt {
	return func(s *Server) error {
		if c != nil {
			s.client = c
		}
		return nil
	}
}
