package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"EFSS/server/db"
	"EFSS/server/middleware"

	"golang.org/x/crypto/argon2"
)

type RegisterRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	PublicKey string `json:"public_key"` // base64
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

func generateSalt() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func hashPassword(password, salt string) string {
	hash := argon2.IDKey([]byte(password), []byte(salt), 1, 64*1024, 4, 32)
	return base64.StdEncoding.EncodeToString(hash)
}

func Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	salt := generateSalt()
	hash := hashPassword(req.Password, salt)

	_, err := db.DB.Exec(
		"INSERT INTO users (username, password_hash, salt, public_key) VALUES ($1, $2, $3, $4)",
		req.Username, hash, salt, req.PublicKey,
	)
	if err != nil {
		http.Error(w, "user already registered or DB error", http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	json.NewDecoder(r.Body).Decode(&req)

	var storedHash, salt string
	err := db.DB.QueryRow(
		"SELECT password_hash, salt FROM users WHERE username = $1", req.Username,
	).Scan(&storedHash, &salt)
	if err != nil {
		http.Error(w, "wrong credentials", http.StatusUnauthorized)
		return
	}

	if hashPassword(req.Password, salt) != storedHash {
		http.Error(w, "wrong credentials", http.StatusUnauthorized)
		return
	}

	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := base64.URLEncoding.EncodeToString(tokenBytes)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	_, err = db.DB.Exec(
		"INSERT INTO sessions (token, username, expires_at) VALUES ($1, $2, $3)",
		token, req.Username, expiresAt,
	)
	if err != nil {
		http.Error(w, "error while creating session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(LoginResponse{Token: token})
}

func Logout(w http.ResponseWriter, r *http.Request) {
	token := middleware.Token(r)

	_, err := db.DB.Exec("DELETE FROM sessions WHERE token = $1", token)
	if err != nil {
		http.Error(w, "logout error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
