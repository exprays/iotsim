package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// RequestLoggingMiddleware logs information about each request
func (r *Router) RequestLoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()

		// Call the next handler
		next.ServeHTTP(w, req)

		// Log request information
		duration := time.Since(start)
		fmt.Printf("[%s] %s %s %s\n",
			time.Now().Format(time.RFC3339),
			req.Method,
			req.RequestURI,
			duration,
		)
	})
}

// GlobalCORSMiddleware handles Cross-Origin Resource Sharing
func (r *Router) GlobalCORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Check if origin is in allowed origins
		origin := req.Header.Get("Origin")
		allowedOrigins := r.config.AllowedOrigins

		// If * is in allowed origins, allow all
		if contains(allowedOrigins, "*") {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		} else if origin != "" && contains(allowedOrigins, origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}

		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours

		// Handle preflight requests
		if req.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Call the next handler
		next.ServeHTTP(w, req)
	})
}

// JWTAuthMiddleware verifies JWT tokens for authenticated endpoints
func (r *Router) JWTAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Get token from Authorization header
		authHeader := req.Header.Get("Authorization")
		if authHeader == "" {
			respondWithError(w, http.StatusUnauthorized, "missing authorization header")
			return
		}

		// Extract token string
		tokenString := ""
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			tokenString = parts[1]
		} else {
			respondWithError(w, http.StatusUnauthorized, "invalid authorization format, must be 'Bearer {token}'")
			return
		}

		// Parse and validate token
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			// Validate the signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(r.config.JWTSecret), nil
		})

		if err != nil || !token.Valid {
			respondWithError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}

		// Add claims to request context
		ctx := context.WithValue(req.Context(), "userID", claims.UserID)
		ctx = context.WithValue(ctx, "username", claims.Username)
		ctx = context.WithValue(ctx, "roles", claims.Roles)

		// Call the next handler with the enriched context
		next.ServeHTTP(w, req.WithContext(ctx))
	})
}

// RateLimitMiddleware limits the number of requests per IP
func (r *Router) RateLimitMiddleware(next http.Handler) http.Handler {
	// In a real implementation, you would use a proper rate limiter
	// This is a simplified version
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Call the next handler
		next.ServeHTTP(w, req)
	})
}

// Claims represents the claims in a JWT token
type Claims struct {
	UserID   string   `json:"userId"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	jwt.RegisteredClaims
}

// Helper function to check if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
