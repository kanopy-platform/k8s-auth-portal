package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleRoot(t *testing.T) {
	tests := []*http.Request{
		httptest.NewRequest("GET", "/", nil),
	}

	s := New()

	for _, req := range tests {
		w := httptest.NewRecorder()

		s.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Errorf("response code %d should be 200", w.Code)
		}
	}
}
