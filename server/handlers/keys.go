package handlers

import (
	"encoding/json"
	"net/http"

	"efss-server/db"
)

// GetPublicKey handles the retrieval of a user's public key.
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
