package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBearerAuthMiddleware(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	h := bearerAuthMiddleware("abc", next)

	t.Run("missing token", func(t *testing.T) {
		nextCalled = false
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		if res.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 got %d", res.Code)
		}
		if nextCalled {
			t.Fatalf("next handler should not be called")
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		nextCalled = false
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Authorization", "Bearer bad")
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		if res.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 got %d", res.Code)
		}
		if nextCalled {
			t.Fatalf("next handler should not be called")
		}
	})

	t.Run("valid token", func(t *testing.T) {
		nextCalled = false
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Authorization", "Bearer abc")
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("expected 200 got %d", res.Code)
		}
		if !nextCalled {
			t.Fatalf("next handler should be called")
		}
	})
}
