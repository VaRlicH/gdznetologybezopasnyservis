package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lib/pq"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_]{3,30}$`)

// Выполняем bcrypt и для неизвестного email, уменьшая разницу во времени ответа.
var dummyPasswordHash, _ = HashPassword("dummy-password-for-login")

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	sendErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
	return false
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	var req RegisterRequest
	if err := parseJSONRequest(r, &req); err != nil {
		sendErrorResponse(w, "Invalid JSON request", 400)
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Username = strings.TrimSpace(req.Username)
	if err := validateRegisterRequest(&req); err != nil {
		sendErrorResponse(w, err.Error(), 400)
		return
	}
	exists, err := UserExistsByEmail(req.Email)
	if err != nil {
		internalError(w, err)
		return
	}
	if exists {
		sendErrorResponse(w, "Email or username already exists", 409)
		return
	}
	hash, err := HashPassword(req.Password)
	if err != nil {
		internalError(w, err)
		return
	}
	user, err := CreateUser(req.Email, req.Username, hash)
	if err != nil {
		var pgErr *pq.Error
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			sendErrorResponse(w, "Email or username already exists", 409)
			return
		}
		internalError(w, err)
		return
	}
	sendAuthResponse(w, user, http.StatusCreated)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	var req LoginRequest
	if err := parseJSONRequest(r, &req); err != nil {
		sendErrorResponse(w, "Invalid JSON request", 400)
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if err := validateLoginRequest(&req); err != nil {
		sendErrorResponse(w, err.Error(), 400)
		return
	}
	user, err := GetUserByEmail(req.Email)
	if errors.Is(err, sql.ErrNoRows) {
		CheckPassword(req.Password, dummyPasswordHash)
		sendErrorResponse(w, "Invalid email or password", 401)
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	if !CheckPassword(req.Password, user.PasswordHash) {
		sendErrorResponse(w, "Invalid email or password", 401)
		return
	}
	sendAuthResponse(w, user, http.StatusOK)
}

func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	id, ok := GetUserIDFromContext(r)
	if !ok {
		sendErrorResponse(w, "Unauthorized", 401)
		return
	}
	user, err := GetUserByID(id)
	if errors.Is(err, sql.ErrNoRows) {
		sendErrorResponse(w, "User not found", 404)
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	sendJSONResponse(w, user, http.StatusOK)
}

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if db == nil || db.PingContext(ctx) != nil {
		sendErrorResponse(w, "Database unavailable", 503)
		return
	}
	sendJSONResponse(w, map[string]string{"status": "ok", "message": "Service is running"}, 200)
}

func sendAuthResponse(w http.ResponseWriter, user *User, status int) {
	token, err := GenerateToken(*user)
	if err != nil {
		internalError(w, err)
		return
	}
	sendJSONResponse(w, AuthResponse{Token: token, User: *user}, status)
}

func internalError(w http.ResponseWriter, err error) {
	log.Printf("Request failed (%T)", err)
	sendErrorResponse(w, "Internal server error", 500)
}

func sendJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Encode response: %v", err)
	}
}

func sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	sendJSONResponse(w, map[string]string{"error": message}, statusCode)
}

func parseJSONRequest(r *http.Request, v interface{}) error {
	if r.Body == nil {
		return fmt.Errorf("request body is empty")
	}
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("expected a single JSON object")
	}
	return nil
}

func validateRegisterRequest(req *RegisterRequest) error {
	if err := ValidateEmail(req.Email); err != nil {
		return err
	}
	if !usernamePattern.MatchString(req.Username) {
		return fmt.Errorf("username must contain 3-30 ASCII letters, digits or underscores")
	}
	return ValidatePassword(req.Password)
}

func validateLoginRequest(req *LoginRequest) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}
	return nil
}
