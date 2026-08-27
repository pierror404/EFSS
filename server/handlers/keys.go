package handlers

import (
	"encoding/json"
	"net/http"

	"EFSS/server/db"
)

type PublicKeyResponse struct {
	Username  string `json:"username"`
	PublicKey string `json:"public_key"`
}

func GetPublicKey(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")

	var publicKey string
	err := db.DB.QueryRow(
		"SELECT public_key FROM users WHERE username = $1", username,
	).Scan(&publicKey)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(PublicKeyResponse{
		Username:  username,
		PublicKey: publicKey,
	})
}
