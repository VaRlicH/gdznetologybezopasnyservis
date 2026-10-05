package main

import (
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func setupAuth(t *testing.T) {
	t.Helper()
	previous := jwtSecret
	t.Setenv("JWT_SECRET", strings.Repeat("test-secret-", 4))
	InitAuth()
	t.Cleanup(func() { jwtSecret = previous })
}

func TestPasswords(t *testing.T) {
	hash, err := HashPassword("SecurePass123")
	if err != nil || hash == "SecurePass123" || !CheckPassword("SecurePass123", hash) {
		t.Fatalf("bcrypt round trip failed: %v", err)
	}
	if CheckPassword("wrong", hash) || CheckPassword("password", "invalid-hash") {
		t.Fatal("invalid password accepted")
	}
	for _, password := range []string{"short", strings.Repeat("x", 73), strings.Repeat("я", 37)} {
		if ValidatePassword(password) == nil {
			t.Fatal("invalid password length accepted")
		}
	}
}

func TestTokens(t *testing.T) {
	setupAuth(t)
	user := User{ID: 7, Email: "test@example.com", Username: "testuser"}
	token, err := GenerateToken(user)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ValidateToken(token)
	if err != nil || claims.UserID != user.ID || claims.Email != user.Email || claims.Username != user.Username {
		t.Fatalf("token round trip: %v", err)
	}
	if claims.ExpiresAt.Sub(claims.IssuedAt.Time) != 24*time.Hour {
		t.Fatal("unexpected token lifetime")
	}
	for _, tc := range []struct {
		name   string
		method jwt.SigningMethod
		key    interface{}
		expiry *jwt.NumericDate
		id     int
	}{
		{"expired", jwt.SigningMethodHS256, jwtSecret, jwt.NewNumericDate(time.Now().Add(-time.Hour)), 7},
		{"no expiration", jwt.SigningMethodHS256, jwtSecret, nil, 7},
		{"wrong key", jwt.SigningMethodHS256, []byte(strings.Repeat("other", 10)), jwt.NewNumericDate(time.Now().Add(time.Hour)), 7},
		{"wrong algorithm", jwt.SigningMethodHS384, jwtSecret, jwt.NewNumericDate(time.Now().Add(time.Hour)), 7},
		{"unsigned", jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, jwt.NewNumericDate(time.Now().Add(time.Hour)), 7},
		{"invalid user", jwt.SigningMethodHS256, jwtSecret, jwt.NewNumericDate(time.Now().Add(time.Hour)), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Claims{UserID: tc.id, Email: user.Email, Username: user.Username, RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: tc.expiry, IssuedAt: jwt.NewNumericDate(time.Now())}}
			bad, err := jwt.NewWithClaims(tc.method, c).SignedString(tc.key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ValidateToken(bad); err == nil {
				t.Fatal("invalid token accepted")
			}
		})
	}
	if _, err := ValidateToken("malformed"); err == nil {
		t.Fatal("malformed token accepted")
	}
}

func TestMiddleware(t *testing.T) {
	setupAuth(t)
	token, err := GenerateToken(User{ID: 5, Email: "user@example.com", Username: "user"})
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{"", "Bearer", "Basic abc", "Bearer broken", "Bearer " + token + " extra", "Bearer " + token} {
		called := false
		handler := AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
			called = true
			id, ok := GetUserIDFromContext(r)
			if !ok || id != 5 {
				t.Error("missing user context")
			}
			w.WriteHeader(204)
		})
		r := httptest.NewRequest("GET", "/profile", nil)
		r.Header.Set("Authorization", header)
		w := httptest.NewRecorder()
		handler(w, r)
		want := 401
		if header == "Bearer "+token {
			want = 204
		}
		if w.Code != want || called != (want == 204) {
			t.Fatalf("middleware got %d, want %d", w.Code, want)
		}
	}
}

func TestInvalidRequests(t *testing.T) {
	for _, body := range []string{"", "{", "null", `{}`, `{"email":"bad","username":"test","password":"SecurePass123"}`, `{"extra":true}`, `{} {}`, strings.Repeat(" ", 8193) + `{}`} {
		w := httptest.NewRecorder()
		RegisterHandler(w, httptest.NewRequest("POST", "/register", strings.NewReader(body)))
		if w.Code != 400 {
			t.Fatalf("bad registration got %d", w.Code)
		}
	}
	for _, handler := range []http.HandlerFunc{RegisterHandler, LoginHandler, ProfileHandler, HealthHandler} {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest("DELETE", "/", nil))
		if w.Code != 405 || w.Header().Get("Allow") == "" {
			t.Fatal("method not rejected")
		}
	}
}
