package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"
)

var idTokenString string

type MockOIDCClient struct{}

func (m *MockOIDCClient) NewProvider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	return &oidc.Provider{}, nil
}

type MockOauth2Config struct{}

func (m *MockOauth2Config) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	u := url.URL{
		Scheme: "https",
		Host:   "dex.example.com",
		Path:   "auth",
	}

	v := url.Values{}
	v.Set("state", state)

	u.RawQuery = v.Encode()
	return u.String()
}

func (m *MockOauth2Config) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	oauth2Token := &oauth2.Token{
		AccessToken:  "",
		TokenType:    "",
		RefreshToken: "",
		Expiry:       time.Now().Add(1 * time.Hour),
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, fmt.Errorf("mock: error from GenerateKey: %v", err)
	}

	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":            "",
		"aud":            "kubectl",
		"exp":            time.Now().Add(1 * time.Hour).Unix(),
		"nonce":          "",
		"email":          "kilgore@kilgore.trout",
		"email_verified": true,
		"name":           "Kilgore Trout",
	})

	idTokenString, err = idToken.SignedString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("mock: error from SignedString: %v", err)
	}

	rawField := map[string]interface{}{
		"id_token": idTokenString,
	}

	return oauth2Token.WithExtra(rawField), nil
}

type MockKeySet struct {
}

func (ks *MockKeySet) VerifySignature(ctx context.Context, jwt string) (payload []byte, err error) {
	// Need to extract payload from JWT
	// The payload extraction needs to be equivalent to oidc.parseJWT()
	parts := strings.Split(idTokenString, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("mock: malformed jwt, expected 3 parts got %d", len(parts))
	}

	payload, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("mock: malformed jwt payload: %v", err)
	}
	return payload, nil
}
