package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"efss-server/db"
)

type contextKey string

const (
	UsernameKey contextKey = "username"
	TokenKey    contextKey = "token"
)

func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "token mancante", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")

		var username string
		var expiresAt time.Time
		err := db.DB.QueryRow(
			"SELECT username, expires_at FROM sessions WHERE token = $1",
			token,
		).Scan(&username, &expiresAt)

		if err != nil {
			http.Error(w, "token non valido", http.StatusUnauthorized)
			return
		}

		if time.Now().After(expiresAt) {
			http.Error(w, "token scaduto", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), UsernameKey, username)
		ctx = context.WithValue(ctx, TokenKey, token)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func Username(r *http.Request) string {
	username, _ := r.Context().Value(UsernameKey).(string)
	return username
}

func Token(r *http.Request) string {
	token, _ := r.Context().Value(TokenKey).(string)
	return token
}
