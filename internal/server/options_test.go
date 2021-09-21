package server

import (
	"encoding/base64"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

type optTest struct {
	opts []ServerFuncOpt
}

func TestOptions(t *testing.T) {
	t.Parallel()

	// Test with default parameters
	s, err := New(
		WithSessionName(""),
		WithSessionSecret(""),
		WithAPIServerURL(""),
		WithIssuerURL(""),
		WithExtraScopes(""),
		WithClusterCA(""),
		WithKubectlClientID(""),
		WithKubectlClientSecret(""),
	)
	assert.NoError(t, err)
	assert.NotEmpty(t, s.(*Server).sessionName)
	assert.NotEmpty(t, s.(*Server).sessionSecret)
	assert.NotEmpty(t, s.(*Server).apiServerURL)
	assert.NotEmpty(t, s.(*Server).issuerURL)
	assert.Empty(t, s.(*Server).clusterCA)
	assert.NotEmpty(t, s.(*Server).oauth2Config.ClientID)
	assert.NotEmpty(t, s.(*Server).oauth2Config.ClientSecret)
	assert.NotEmpty(t, s.(*Server).oauth2Config.RedirectURL)
	assert.Len(t, s.(*Server).oauth2Config.Scopes, 5)

	// Test setting all options
	const wantSecret = "dummy-secret"
	const testAPIServerURL = "http://another.example.com"
	const testIssuerURL = "https://dex.example.com"

	wantAPIServerURL, err := url.Parse(testAPIServerURL)
	assert.NoError(t, err)
	wantIssuerURL, err := url.Parse(testIssuerURL)
	assert.NoError(t, err)

	const testCrtPath = "testdata/test.crt"
	crtData, err := os.ReadFile(testCrtPath)
	assert.NoError(t, err)

	s, err = New(
		WithSessionName("test"),
		WithSessionSecret("test"),
		WithAPIServerURL(testAPIServerURL),
		WithIssuerURL(testIssuerURL),
		WithExtraScopes("claim"),
		WithClusterCA(testCrtPath),
		WithKubectlClientID("test"),
		WithKubectlClientSecret("testdata/test-secret-exists"),
	)
	assert.NoError(t, err)
	assert.Equal(t, "test", s.(*Server).sessionName)
	assert.Equal(t, "test", s.(*Server).sessionSecret)
	assert.Equal(t, wantAPIServerURL, s.(*Server).apiServerURL)
	assert.Equal(t, wantIssuerURL, s.(*Server).issuerURL)
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte(crtData)), s.(*Server).clusterCA)
	assert.Equal(t, "test", s.(*Server).oauth2Config.ClientID)
	assert.Equal(t, wantSecret, s.(*Server).oauth2Config.ClientSecret)
	assert.NotEmpty(t, s.(*Server).oauth2Config.RedirectURL)
	assert.Len(t, s.(*Server).oauth2Config.Scopes, 6)

	// Test invalid options
	errorTests := []optTest{
		{
			opts: []ServerFuncOpt{
				WithAPIServerURL("not-a-url"),
			},
		},

		{
			opts: []ServerFuncOpt{
				WithIssuerURL("not-a-url"),
			},
		},

		{
			opts: []ServerFuncOpt{
				WithClusterCA("testdata/pathnotfound"),
			},
		},
		{
			opts: []ServerFuncOpt{
				WithKubectlClientSecret("testdata/pathnotfound"),
			},
		},
	}

	for _, test := range errorTests {
		_, err := New(test.opts...)
		assert.Error(t, err)
	}
}
