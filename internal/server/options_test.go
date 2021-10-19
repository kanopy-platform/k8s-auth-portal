package server

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

type optTest struct {
	opts []ServerFuncOpt
}

func readFileToString(filePath string) (string, error) {
	byteData, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	return string(byteData), nil
}

func TestOptions(t *testing.T) {
	t.Parallel()

	client := &http.Client{
		Transport: NewOidcProviderRoundTripper().WithProviderInfo(),
	}

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
		WithHTTPClient(client),
	)
	assert.NoError(t, err)
	assert.NotNil(t, s.client)
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

	const testSessionSecretPath = "testdata/session-secret"
	wantSessionSecret, err := readFileToString(testSessionSecretPath)
	assert.NoError(t, err)

	const testClientSecretPath = "testdata/client-secret"
	wantClientSecret, err := readFileToString(testClientSecretPath)
	assert.NoError(t, err)

	s, err = New(
		WithSessionName("test"),
		WithSessionSecret(testSessionSecretPath),
		WithAPIServerURL(testAPIServerURL),
		WithIssuerURL(testIssuerURL),
		WithExtraScopes("claim"),
		WithClusterCA(testCrtPath),
		WithKubectlClientID("test"),
		WithKubectlClientSecret(testClientSecretPath),
		WithHTTPClient(client),
	)
	assert.NoError(t, err)
	assert.NotNil(t, s.client)
	assert.Equal(t, "test", s.sessionName)
	assert.Equal(t, wantSessionSecret, s.sessionSecret)
	assert.Equal(t, wantAPIServerURL, s.apiServerURL)
	assert.Equal(t, wantIssuerURL, s.issuerURL)
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte(crtData)), s.clusterCA)
	assert.Equal(t, "test", s.kubectlClientID)
	assert.Equal(t, wantClientSecret, s.kubectlClientSecret)
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
				WithSessionSecret("testdata/pathnotfound"),
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
