package handlers

// RegisterRequest represents the request payload for user registration.
type RegisterRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	PublicKey string `json:"public_key"` // base64
}

// LoginRequest represents the request payload for user login.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents the response payload for a successful login.
type LoginResponse struct {
	Token string `json:"token"`
}

// RecipientKey represents a recipient and their encrypted symmetric key.
type RecipientKey struct {
	Username              string `json:"username"`
	EncryptedSymmetricKey string `json:"encrypted_symmetric_key"` // base64
}

// SendRequest represents the request payload for sending a message.
type SendRequest struct {
	Filename      string         `json:"filename"`
	EncryptedBlob string         `json:"encrypted_blob"` // base64
	Signature     string         `json:"signature"`      // base64
	Recipients    []RecipientKey `json:"recipients"`
}

// InboxItem represents a message in the user's inbox.
type InboxItem struct {
	MessageID int    `json:"message_id"`
	Sender    string `json:"sender"`
	Filename  string `json:"filename"`
}

// DownloadResponse represents the response payload for downloading a message.
type DownloadResponse struct {
	Sender                string `json:"sender"`
	Filename              string `json:"filename"`
	EncryptedBlob         string `json:"encrypted_blob"`
	Signature             string `json:"signature"`
	EncryptedSymmetricKey string `json:"encrypted_symmetric_key"`
}

// PublicKeyResponse represents the response payload for a public key request.
type PublicKeyResponse struct {
	Username  string `json:"username"`
	PublicKey string `json:"public_key"`
}
