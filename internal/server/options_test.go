package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptions(t *testing.T) {
	t.Parallel()

	s, err := New(
		WithSessionName(""),
		WithSessionSecret(""),
	)
	assert.NoError(t, err)
	assert.NotEmpty(t, s.(*Server).sessionName)
	assert.NotEmpty(t, s.(*Server).sessionSecret)

	s, err = New(
		WithSessionName("test"),
		WithSessionSecret("test"),
	)
	assert.NoError(t, err)
	assert.Equal(t, "test", s.(*Server).sessionName)
	assert.Equal(t, "test", s.(*Server).sessionSecret)
}
