package main

import (
	"context"
	"net/http"
	"strings"
)

type contextKey uint8

const userIDKey contextKey = iota

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Fields(r.Header.Get("Authorization"))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 4096 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			sendErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		claims, err := ValidateToken(parts[1])
		if err != nil {
			w.Header().Set("WWW-Authenticate", "Bearer")
			sendErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), userIDKey, claims.UserID)))
	}
}

func GetUserIDFromContext(r *http.Request) (int, bool) {
	id, ok := r.Context().Value(userIDKey).(int)
	return id, ok && id > 0
}
