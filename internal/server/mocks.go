package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/oauth2"
)

var idTokenString string
var testNonce string
var testCodeChallenge string

type mockOauth2Config struct{}

func (m *mockOauth2Config) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	u := url.URL{
		Scheme: "https",
		Host:   "dex.example.com",
		Path:   "auth",
	}

	v := url.Values{}
	v.Set("state", state)

	// Check for PKCE code_challenge option
	for _, opt := range opts {
		switch o := opt.(type) {
		case oauth2.AuthCodeOption:
			if strings.Contains(fmt.Sprintf("%v", o), "code_challenge") {
				codeChallenge := fmt.Sprintf("%v", o)
				v.Set("code_challenge", codeChallenge)
				v.Set("code_challenge_method", "S256")
				testCodeChallenge = codeChallenge
			}
		}
	}

	u.RawQuery = v.Encode()
	return u.String()
}

func (m *mockOauth2Config) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	oauth2Token := &oauth2.Token{
		AccessToken:  "",
		TokenType:    "",
		RefreshToken: "",
		Expiry:       time.Now().Add(1 * time.Hour),
	}

	var codeVerifier string
	for _, opt := range opts {
		// transforms code_verifier to a string for mocking purposes
		optStr := fmt.Sprintf("%v", opt)
		if strings.Contains(optStr, "code_verifier") {
			codeVerifier = strings.TrimPrefix(optStr, "{code_verifier ")
			codeVerifier = strings.TrimSuffix(codeVerifier, "}")
			break
		}
	}

	if codeVerifier == "" {
		return nil, fmt.Errorf("mock: code_verifier is missing")
	}

	hasher := sha256.New()
	hasher.Write([]byte(codeVerifier))
	actualChallenge := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))

	// Compare the computed code_challenge with the one stored in testCodeChallenge
	if actualChallenge != testCodeChallenge {
		return nil, fmt.Errorf("mock: code_verifier does not match the expected challenge")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, fmt.Errorf("mock: error from GenerateKey: %v", err)
	}

	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":            "",
		"aud":            "kubectl",
		"exp":            time.Now().Add(1 * time.Hour).Unix(),
		"nonce":          testNonce,
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

type mockKeySet struct{}

func (ks *mockKeySet) VerifySignature(ctx context.Context, jwt string) (payload []byte, err error) {
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
