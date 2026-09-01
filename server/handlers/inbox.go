package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"efss-server/db"
	"efss-server/middleware"
)

// SendMessage handles the sending of a message to multiple recipients.
func SendMessage(w http.ResponseWriter, r *http.Request) {
	sender := middleware.Username(r)

	var req SendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	blob, err := base64.StdEncoding.DecodeString(req.EncryptedBlob)
	if err != nil {
		http.Error(w, "invalid blob", http.StatusBadRequest)
		return
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		http.Error(w, "invalid signature", http.StatusBadRequest)
		return
	}

	tx, err := db.DB.Begin()
	if err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	var messageID int
	err = tx.QueryRow(
		`INSERT INTO messages (sender_username, encrypted_blob, signature, original_filename)
		 VALUES ($1, $2, $3, $4) RETURNING message_id`,
		sender, blob, sig, req.Filename,
	).Scan(&messageID)
	if err != nil {
		tx.Rollback()
		http.Error(w, "error while writing message", http.StatusInternalServerError)
		return
	}
	//messageID, _ := res.LastInsertId()

	for _, rec := range req.Recipients {
		keyBytes, err := base64.StdEncoding.DecodeString(rec.EncryptedSymmetricKey)
		if err != nil {
			tx.Rollback()
			http.Error(w, "invalid key for "+rec.Username, http.StatusBadRequest)
			return
		}

		_, err = tx.Exec(
			`INSERT INTO message_recipients (message_id, recipient_username, encrypted_symmetric_key)
			 VALUES ($1, $2, $3)`,
			messageID, rec.Username, keyBytes,
		)
		if err != nil {
			tx.Rollback()
			http.Error(w, "error inserting recipient: "+rec.Username, http.StatusInternalServerError)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "commit error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// Inbox handles the retrieval of messages in the user's inbox.
func Inbox(w http.ResponseWriter, r *http.Request) {
	username := middleware.Username(r)

	rows, err := db.DB.Query(
		`SELECT m.message_id, m.sender_username, m.original_filename
		 FROM messages m
		 JOIN message_recipients mr ON m.message_id = mr.message_id
		 WHERE mr.recipient_username = $1 AND mr.delivered = FALSE`,
		username,
	)
	if err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var items []InboxItem
	for rows.Next() {
		var item InboxItem
		if err := rows.Scan(&item.MessageID, &item.Sender, &item.Filename); err != nil {
			http.Error(w, "error while reading results", http.StatusInternalServerError)
			return
		}
		items = append(items, item)
	}

	if err := rows.Err(); err != nil {
		http.Error(w, "results iteration error", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(items)
}

// Download handles the downloading of a message for a recipient.
func Download(w http.ResponseWriter, r *http.Request) {
	username := middleware.Username(r)
	messageID := r.PathValue("id")

	var resp DownloadResponse
	var blob, sig, key []byte

	err := db.DB.QueryRow(
		`SELECT m.sender_username, m.original_filename, m.encrypted_blob, m.signature,
		        mr.encrypted_symmetric_key
		 FROM messages m
		 JOIN message_recipients mr ON m.message_id = mr.message_id
		 WHERE m.message_id = $1 AND mr.recipient_username = $2`,
		messageID, username,
	).Scan(&resp.Sender, &resp.Filename, &blob, &sig, &key)

	if err != nil {
		http.Error(w, "message not found", http.StatusNotFound)
		return
	}

	resp.EncryptedBlob = base64.StdEncoding.EncodeToString(blob)
	resp.Signature = base64.StdEncoding.EncodeToString(sig)
	resp.EncryptedSymmetricKey = base64.StdEncoding.EncodeToString(key)

	json.NewEncoder(w).Encode(resp)

	// Mark the message as delivered
	db.DB.Exec(
		`UPDATE message_recipients SET delivered = TRUE, delivered_at = CURRENT_TIMESTAMP
		 WHERE message_id = $1 AND recipient_username = $2`,
		messageID, username,
	)
}
