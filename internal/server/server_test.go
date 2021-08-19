package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

var s http.Handler

func TestMain(m *testing.M) {
	s = New()
	os.Exit(m.Run())
}

func TestHandleRoot(t *testing.T) {
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	assert.Equal(t, http.StatusOK, w.Code)
}
