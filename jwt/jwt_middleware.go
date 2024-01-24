package jwt

import (
	"context"
	"net/http"
)

const (
	// TokenCookieKey is the key of the cookie stored in the context.
	TokenCookieKey = "session_token"
)

type claimsContextKey struct{}

// Middleware is a middleware that inject the JWT in the context for HTTP servers.
func (jwt Secret) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the JWT token from the request header
		cookie, err := r.Cookie(TokenCookieKey)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		// Verify the JWT token
		claims, err := jwt.VerifyToken(cookie.Value)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		// Store the claims in the request context for further use
		ctx := context.WithValue(r.Context(), claimsContextKey{}, *claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Deny is an authentication guard for HTTP servers.
func Deny(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := GetClaimsFromRequest(r)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// GetClaimsFromRequest is a helper function to fetch the JWT session token from an HTTP request.
func GetClaimsFromRequest(r *http.Request) (claims Claims, ok bool) {
	claims, ok = r.Context().Value(claimsContextKey{}).(Claims)
	return claims, ok
}
