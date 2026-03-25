package server

import (
	"log"
	"net/http"
	"strings"
)

func bearerAuthMiddleware(expectedToken string, next http.Handler) http.Handler {
	return bearerAuthMiddlewareWithLogger(expectedToken, next, nil, false)
}

func bearerAuthMiddlewareWithLogger(expectedToken string, next http.Handler, logger *log.Logger, debug bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if debug && logger != nil {
			logger.Printf("[DEBUG] auth request: method=%s path=%s remote=%s", r.Method, r.URL.Path, r.RemoteAddr)
		}

		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			if debug && logger != nil {
				logger.Printf("[DEBUG] auth failed: missing bearer token")
			}
			http.Error(w, "Unauthorized: Missing Bearer token", http.StatusUnauthorized)
			return
		}

		providedToken := strings.TrimPrefix(authHeader, "Bearer ")
		if providedToken != expectedToken {
			if debug && logger != nil {
				logger.Printf("[DEBUG] auth failed: invalid bearer token")
			}
			http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
			return
		}

		if debug && logger != nil {
			logger.Printf("[DEBUG] auth success")
		}

		next.ServeHTTP(w, r)
	})
}
