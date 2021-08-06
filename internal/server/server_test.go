package server

import (
	"net/http/httptest"
	"testing"
)

func TestHandleRoot(t *testing.T) {
	tests := []struct {
		method string
		path   string
	}{
		{method: "GET", path: "/"},
	}

	s := New()

	for _, test := range tests {
		req := httptest.NewRequest(test.method, test.path, nil)
		w := httptest.NewRecorder()

		s.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Error("test failed")
		}
	}
}
