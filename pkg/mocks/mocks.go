package mocks

import (
	"context"
	"errors"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func MockOidcNewProvider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	return &oidc.Provider{}, nil
}

func MockOauth2ConfigExchange(c *oauth2.Config, ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	oauth2Token := &oauth2.Token{
		AccessToken:  "",
		TokenType:    "",
		RefreshToken: "",
		Expiry:       time.Now().Add(1 * time.Hour),
	}

	rawField := map[string]interface{}{
		"id_token": "",
	}

	return oauth2Token.WithExtra(rawField), nil
}

func MockOauth2ConfigExchangeError(c *oauth2.Config, ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return nil, errors.New("some error")
}

func MockOidcIDTokenVerifierVerify(v *oidc.IDTokenVerifier, ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	return &oidc.IDToken{}, nil
}

func MockOidcIDTokenVerifierVerifyError(v *oidc.IDTokenVerifier, ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	return nil, errors.New("some error")
}

func MockOidcIDTokenClaims(i *oidc.IDToken, v interface{}) error {
	return nil
}

func MockOidcIDTokenClaimsError(i *oidc.IDToken, v interface{}) error {
	return errors.New("some error")
}
