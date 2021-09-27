package server

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OIDCClientProvider interface {
	NewProvider(ctx context.Context, issuer string) (*oidc.Provider, error)
}

type OIDCClient struct{}

func (o *OIDCClient) NewProvider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	return oidc.NewProvider(ctx, issuer)
}

type Oauth2ConfigProvider interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
}

type OIDCIDTokenVerifier interface {
	Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)
}
