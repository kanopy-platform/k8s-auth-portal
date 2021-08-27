package random

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecureString(t *testing.T) {
	s1, err := SecureString(32)
	assert.NoError(t, err)
	assert.Len(t, s1, 32)

	s2, err := SecureString(32)
	assert.NoError(t, err)
	assert.Len(t, s2, 32)

	assert.NotEqual(t, s1, s2)

	_, err = SecureString(-1)
	assert.Error(t, err)
}
