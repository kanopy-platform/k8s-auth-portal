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
	assert.NotEmpty(t, s.sessionName)
	assert.NotEmpty(t, s.sessionSecret)
	assert.NotEmpty(t, s.apiServerURL)
	assert.NotEmpty(t, s.issuerURL)
	assert.Empty(t, s.clusterCA)
	assert.NotEmpty(t, s.kubectlClientID)
	assert.NotEmpty(t, s.kubectlClientSecret)
	assert.Len(t, s.scopes, 5)

	// Test setting all options
	const testAPIServerURL = "http://another.example.com"
	const testIssuerURL = "https://dex.example.com"

	wantAPIServerURL, err := url.Parse(testAPIServerURL)
	assert.NoError(t, err)
	wantIssuerURL, err := url.Parse(testIssuerURL)
	assert.NoError(t, err)

	const testCrtPath = "testdata/test.crt"
	crtData, err := os.ReadFile(testCrtPath)
	assert.NoError(t, err)

	const testSecretPath = "testdata/test-secret"
	secretByteData, err := os.ReadFile(testSecretPath)
	assert.NoError(t, err)
	wantSecret := string(secretByteData)

	s, err = New(
		WithSessionName("test"),
		WithSessionSecret("test"),
		WithAPIServerURL(testAPIServerURL),
		WithIssuerURL(testIssuerURL),
		WithExtraScopes("claim"),
		WithClusterCA(testCrtPath),
		WithKubectlClientID("test"),
		WithKubectlClientSecret(testSecretPath),
	)
	assert.NoError(t, err)
	assert.Equal(t, "test", s.sessionName)
	assert.Equal(t, "test", s.sessionSecret)
	assert.Equal(t, wantAPIServerURL, s.apiServerURL)
	assert.Equal(t, wantIssuerURL, s.issuerURL)
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte(crtData)), s.clusterCA)
	assert.Equal(t, "test", s.kubectlClientID)
	assert.Equal(t, wantSecret, s.kubectlClientSecret)
	assert.Len(t, s.scopes, 6)

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
