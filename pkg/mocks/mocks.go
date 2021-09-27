package mocks

import (
	"context"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

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

	//hmacSampleSecret := []byte("replace_this_public_client_secret")
	// privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	// if err != nil {
	// 	log.Printf("failed to GenerateKey %v", err)
	// }

	// idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
	// 	"iss":            "",
	// 	"aud":            "kubectl",
	// 	"exp":            time.Now().Add(1 * time.Hour).Unix(),
	// 	"nonce":          "",
	// 	"email":          "kilgore@kilgore.trout",
	// 	"email_verified": true,
	// 	"name":           "Kilgore Trout",
	// })

	// idTokenString, err := idToken.SignedString(privateKey)
	// if err != nil {
	// 	log.Printf("SignedString failed %v", err)
	// }

	// log.Printf("idTokenString: %v", idTokenString)

	// rawField := map[string]interface{}{
	// 	"id_token": idTokenString,
	// }

	rawField := map[string]interface{}{
		"id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImQwNmZmNDc3ODBiODUzZjI3N2EzMTdjYTAwZjcxY2FhOGEzYmU4YTAifQ.eyJpc3MiOiIiLCJzdWIiOiJDZzB3TFRNNE5TMHlPREE0T1Mwd0VnUnRiMk5yIiwiYXVkIjoia3ViZWN0bCIsImV4cCI6MTYzMjUxODE4MiwiaWF0IjoxNjMyNTE4MTIyLCJub25jZSI6IkNyaThPRUE3cGhhRDUxV0FaRklDMnlCRmdnUFphZndqIiwiYXRfaGFzaCI6IkJDNGE5Q2JXb0Zxd19GSmZSTy1IalEiLCJjX2hhc2giOiIyTjBFSDBjZFUtVzZ1NDA2a0p5ckVRIiwiZW1haWwiOiJraWxnb3JlQGtpbGdvcmUudHJvdXQiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZ3JvdXBzIjpbImF1dGhvcnMiXSwibmFtZSI6IktpbGdvcmUgVHJvdXQifQ.xolTW-6vMkbm9KprIDKppajRDXsiWKcl6PDfCmFIVtIQxdVmDz74k13SYMxiMD7p4a4mv1KRM1MAyg0L5K4tm5vYBItOLQ6sEOq5OX9R-yFHly8N8ktd2M9NhiDCTTDQ2rRRrZBM6EWz-PyGjCMsjiSEFJM2bzmQpus2hUAoQGycCKhSRfWVIO6hw9ymG-qtlglBPlYCey6J0hV_W_BRKNREutXONCZtGl1dqxR2watsOPqDcYBvw6A4Fiut1Zpld6Uqp9qNb-EQp9b4CsKdOZmwyHrXfMka-8FIOSxiGsjtNmN2m2N0OFnD2MssdhXG4pm4LB6INIVkRJV83d4Gtg",
	}

	return oauth2Token.WithExtra(rawField), nil
}

type MockOIDCIDTokenVerifier struct{}

func (m *MockOIDCIDTokenVerifier) Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	return &oidc.IDToken{}, nil
}
