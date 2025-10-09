// internal/auth/jwt.go
package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/orbvpn/orbx.protocol/pkg/models"
)

var (
	ErrMissingToken     = errors.New("missing authorization token") // ✓ lowercase
	ErrInvalidToken     = errors.New("invalid token")               // ✓ lowercase
	ErrExpiredToken     = errors.New("token has expired")           // ✓ lowercase
	ErrInvalidSignature = errors.New("invalid token signature")     // ✓ lowercase
)

type contextKey string

const userContextKey contextKey = "user"

// JWTAuthenticator handles JWT token validation
type JWTAuthenticator struct {
	secret []byte
}

// NewJWTAuthenticator creates a new JWT authenticator
func NewJWTAuthenticator(secret string) *JWTAuthenticator {
	return &JWTAuthenticator{
		secret: []byte(secret),
	}
}

// ValidateToken validates a JWT token and returns user claims
func (j *JWTAuthenticator) ValidateToken(tokenString string) (*models.UserClaims, error) {
	// Parse token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.secret, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		if errors.Is(err, jwt.ErrSignatureInvalid) {
			return nil, ErrInvalidSignature
		}
		return nil, ErrInvalidToken
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	// Parse claims into UserClaims
	userClaims := &models.UserClaims{
		UserID:           int(claims["user_id"].(float64)),
		Username:         claims["username"].(string),
		Email:            claims["email"].(string),
		SubscriptionTier: claims["subscription_tier"].(string),
	}

	// Parse timestamps
	if exp, ok := claims["exp"].(float64); ok {
		userClaims.ExpiresAt = time.Unix(int64(exp), 0)
	}
	if iat, ok := claims["iat"].(float64); ok {
		userClaims.IssuedAt = time.Unix(int64(iat), 0)
	}

	// Check expiration
	if userClaims.ExpiresAt.Before(time.Now()) {
		return nil, ErrExpiredToken
	}

	return userClaims, nil
}

// Middleware creates an HTTP middleware for JWT authentication
func Middleware(auth *JWTAuthenticator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing authorization header", http.StatusUnauthorized)
			return
		}

		// Check Bearer prefix
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]

		// Validate token
		claims, err := auth.ValidateToken(tokenString)
		if err != nil {
			if errors.Is(err, ErrExpiredToken) {
				http.Error(w, "Token has expired", http.StatusUnauthorized)
			} else {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
			}
			return
		}

		// Add claims to context
		ctx := context.WithValue(r.Context(), userContextKey, claims)

		// Call next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetUserFromContext extracts user claims from request context
func GetUserFromContext(ctx context.Context) (*models.UserClaims, error) {
	user, ok := ctx.Value(userContextKey).(*models.UserClaims)
	if !ok {
		return nil, errors.New("user not found in context") // ✓ lowercase
	}
	return user, nil
}
