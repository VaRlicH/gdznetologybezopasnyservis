package main

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"net/mail"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

var jwtSecret []byte

func InitAuth() {
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
	if len(jwtSecret) < 32 || strings.HasPrefix(string(jwtSecret), "your-super-secret") {
		panic("JWT_SECRET must be a unique random key of at least 32 bytes")
	}
}

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

func CheckPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func GenerateToken(user User) (string, error) {
	if len(jwtSecret) < 32 {
		return "", fmt.Errorf("JWT secret is not configured")
	}
	now := time.Now()
	claims := Claims{UserID: user.ID, Email: user.Email, Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour))},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret)
}

func ValidateToken(tokenString string) (*Claims, error) {
	if len(jwtSecret) < 32 {
		return nil, fmt.Errorf("JWT secret is not configured")
	}
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuedAt())
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	if !token.Valid || claims.ExpiresAt == nil || claims.IssuedAt == nil || claims.UserID <= 0 || claims.Email == "" || claims.Username == "" {
		return nil, fmt.Errorf("invalid token claims")
	}
	return claims, nil
}

func ValidatePassword(password string) error {
	if utf8.RuneCountInString(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}
	if len(password) > 72 {
		return fmt.Errorf("password must not exceed 72 bytes")
	}
	return nil
}

func ValidateEmail(email string) error {
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || len(email) > 255 {
		return fmt.Errorf("invalid email address")
	}
	return nil
}
