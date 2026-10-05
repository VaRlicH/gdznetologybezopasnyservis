package main

import (
	"context"
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"net"
	"net/url"
	"time"
)

var db *sql.DB

func InitDB() error {
	connection := &url.URL{Scheme: "postgres", Host: net.JoinHostPort(getEnv("DB_HOST", "localhost"), getEnv("DB_PORT", "5432")),
		User: url.UserPassword(getEnv("DB_USER", "postgres"), getEnv("DB_PASSWORD", "postgres")), Path: "/" + getEnv("DB_NAME", "secure_service")}
	connection.RawQuery = url.Values{"sslmode": {getEnv("DB_SSLMODE", "disable")}, "connect_timeout": {"5"}}.Encode()
	pool, err := sql.Open("postgres", connection.String())
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	pool.SetMaxOpenConns(10)
	pool.SetMaxIdleConns(5)
	pool.SetConnMaxLifetime(30 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := pool.PingContext(ctx); err != nil {
		pool.Close()
		return fmt.Errorf("ping database: %w", err)
	}
	db = pool
	return nil
}

func CloseDB() {
	if db != nil {
		db.Close()
	}
}

func CreateUser(email, username, passwordHash string) (*User, error) {
	user := &User{Email: email, Username: username, PasswordHash: passwordHash}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := db.QueryRowContext(ctx, `INSERT INTO users (email, username, password_hash) VALUES ($1, $2, $3) RETURNING id, created_at`, email, username, passwordHash).Scan(&user.ID, &user.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return user, nil
}

func GetUserByEmail(email string) (*User, error) {
	user := &User{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := db.QueryRowContext(ctx, `SELECT id, email, username, password_hash, created_at FROM users WHERE email = $1`, email).Scan(&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	return user, nil
}

func GetUserByID(userID int) (*User, error) {
	user := &User{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := db.QueryRowContext(ctx, `SELECT id, email, username, created_at FROM users WHERE id = $1`, userID).Scan(&user.ID, &user.Email, &user.Username, &user.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get user by ID: %w", err)
	}
	return user, nil
}

func UserExistsByEmail(email string) (bool, error) {
	var exists bool
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`, email).Scan(&exists)
	return exists, err
}

func GetDB() *sql.DB { return db }
