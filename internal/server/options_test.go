package server

import (
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

type optTest struct {
	opts []ServerFuncOpt
}

func TestOptions(t *testing.T) {
	t.Parallel()

	s, err := New(
		WithSessionName(""),
		WithSessionSecret(""),
		WithAPIServerURL(""),
		WithIssuerURL(""),
		WithExtraScopes(""),
		WithKubectlClientID(""),
	)
	assert.NoError(t, err)
	assert.NotEmpty(t, s.(*Server).sessionName)
	assert.NotEmpty(t, s.(*Server).sessionSecret)
	assert.NotEmpty(t, s.(*Server).apiServerURL)
	assert.NotEmpty(t, s.(*Server).issuerURL)
	assert.NotEmpty(t, s.(*Server).kubectlClientID)
	assert.NotEmpty(t, s.(*Server).kubectlClientSecret)
	assert.Len(t, s.(*Server).scopes, 2)

	const wantSecret = "dummy-secret"

	s, err = New(
		WithSessionName("test"),
		WithSessionSecret("test"),
		WithAPIServerURL("http://another.example.com"),
		WithIssuerURL("http://another.example.com"),
		WithExtraScopes("claim"),
		WithClusterCA("testdata/test-secret-exists"),
		WithKubectlClientSecret("testdata/test-secret-exists"),
		WithKubectlClientID("test"),
	)
	assert.NoError(t, err)
	assert.Equal(t, "test", s.(*Server).sessionName)
	assert.Equal(t, "test", s.(*Server).sessionSecret)
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte(wantSecret)), s.(*Server).clusterCA)
	assert.Equal(t, wantSecret, s.(*Server).kubectlClientSecret)
	assert.Equal(t, "test", s.(*Server).kubectlClientID)
	assert.Len(t, s.(*Server).scopes, 3)

	want, err := url.Parse("http://another.example.com")
	assert.NoError(t, err)
	assert.Equal(t, want, s.(*Server).apiServerURL)
	assert.Equal(t, want, s.(*Server).issuerURL)

	// error tests
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
