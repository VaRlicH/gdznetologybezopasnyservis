package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// RUN_DB_TESTS=1 enables tests against the PostgreSQL configured by DB_*.
func TestPostgresAPI(t *testing.T) {
	if os.Getenv("RUN_DB_TESTS") != "1" {
		t.Skip("set RUN_DB_TESTS=1 and DB_* to run PostgreSQL integration tests")
	}
	setupAuth(t)
	if err := InitDB(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(CloseDB)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	email := "test" + suffix + "@example.com"
	username := "test" + suffix
	t.Cleanup(func() {
		if _, err := db.Exec(`DELETE FROM users WHERE email = $1 OR email = $2`, email, "other"+email); err != nil {
			t.Error(err)
		}
	})
	call := func(handler http.HandlerFunc, method, path, body, token string, want int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != want {
			t.Fatalf("%s %s: got %d, want %d: %s", method, path, w.Code, want, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "password") && want < 400 {
			t.Fatal("password leaked in successful response")
		}
		return w
	}
	call(HealthHandler, "GET", "/health", "", "", 200)
	body := fmt.Sprintf(`{"email":%q,"username":%q,"password":"SecurePass123"}`, email, username)
	registration := call(RegisterHandler, "POST", "/register", body, "", 201)
	var registered AuthResponse
	if err := json.Unmarshal(registration.Body.Bytes(), &registered); err != nil {
		t.Fatal(err)
	}
	if registered.Token == "" || registered.User.ID <= 0 {
		t.Fatal("missing registration data")
	}
	saved, err := GetUserByEmail(email)
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword("SecurePass123", saved.PasswordHash) || !strings.HasPrefix(saved.PasswordHash, "$2") {
		t.Fatal("password not stored as bcrypt")
	}
	exists, err := UserExistsByEmail(email)
	if err != nil || !exists {
		t.Fatalf("exists: %v", err)
	}
	call(RegisterHandler, "POST", "/register", body, "", 409)
	call(RegisterHandler, "POST", "/register", strings.Replace(body, email, "other"+email, 1), "", 409)
	login := call(LoginHandler, "POST", "/login", fmt.Sprintf(`{"email":%q,"password":"SecurePass123"}`, email), "", 200)
	var auth AuthResponse
	if err := json.Unmarshal(login.Body.Bytes(), &auth); err != nil {
		t.Fatal(err)
	}
	profile := call(AuthMiddleware(ProfileHandler), "GET", "/profile", "", auth.Token, 200)
	var user User
	if err := json.Unmarshal(profile.Body.Bytes(), &user); err != nil || user.ID != saved.ID {
		t.Fatal("wrong profile")
	}
	call(AuthMiddleware(ProfileHandler), "GET", "/profile", "", "", 401)
	call(AuthMiddleware(ProfileHandler), "GET", "/profile", "", "fake", 401)
	wrong := call(LoginHandler, "POST", "/login", fmt.Sprintf(`{"email":%q,"password":"wrong"}`, email), "", 401)
	missing := call(LoginHandler, "POST", "/login", `{"email":"missing@example.invalid","password":"wrong"}`, "", 401)
	if wrong.Body.String() != missing.Body.String() {
		t.Fatal("login reveals email existence")
	}
	injection := `' OR 1=1; --`
	if _, err := GetUserByEmail(injection); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("SQL injection lookup: %v", err)
	}
	if exists, err := UserExistsByEmail(injection); err != nil || exists {
		t.Fatal("SQL injection exists check")
	}
	call(LoginHandler, "POST", "/login", fmt.Sprintf(`{"email":%q,"password":"SecurePass123"}`, injection), "", 401)
	// INSERT also treats hostile input as data. Remove this test record on exit.
	injected, err := CreateUser("insert"+email, injection, saved.PasswordHash)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := db.Exec(`DELETE FROM users WHERE id = $1`, injected.ID); err != nil {
			t.Error(err)
		}
	})
	found, err := GetUserByID(injected.ID)
	if err != nil || found.Username != injection || found.PasswordHash != "" {
		t.Fatal("parameterized INSERT/profile failed")
	}
	if _, err := db.Exec(`DELETE FROM users WHERE id = $1`, saved.ID); err != nil {
		t.Fatal(err)
	}
	call(AuthMiddleware(ProfileHandler), "GET", "/profile", "", auth.Token, 404)
}
