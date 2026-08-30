package api

import (
	"bytes"
	conf "efss-client/config"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const baseURL = "http://localhost:8080"

func authorizedRequest(method, path string, body any) (*http.Response, error) {
	token, err := conf.LoadToken()
	if err != nil {
		return nil, fmt.Errorf("devi prima fare il login: mycli login <username>")
	}

	var reqBody io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, baseURL+path, reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	return http.DefaultClient.Do(req)
}

func GetPublicKey(username string) (string, error) {
	resp, err := authorizedRequest("GET", "/keys/"+username, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("utente %s non trovato", username)
	}

	var result struct {
		PublicKey string `json:"public_key"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.PublicKey, nil
}

type RecipientKey struct {
	Username              string `json:"username"`
	EncryptedSymmetricKey string `json:"encrypted_symmetric_key"`
}

type SendPayload struct {
	Filename      string         `json:"filename"`
	EncryptedBlob string         `json:"encrypted_blob"`
	Signature     string         `json:"signature"`
	Recipients    []RecipientKey `json:"recipients"`
}

func SendMessage(payload SendPayload) error {
	resp, err := authorizedRequest("POST", "/mailbox/send", payload)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("errore invio: %s", string(body))
	}
	return nil
}

type InboxItem struct {
	MessageID int    `json:"message_id"`
	Sender    string `json:"sender"`
	Filename  string `json:"filename"`
}

func GetInbox() ([]InboxItem, error) {
	resp, err := authorizedRequest("GET", "/mailbox/inbox", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var items []InboxItem
	json.NewDecoder(resp.Body).Decode(&items)
	return items, nil
}

type DownloadResult struct {
	Sender                string `json:"sender"`
	Filename              string `json:"filename"`
	EncryptedBlob         string `json:"encrypted_blob"`
	Signature             string `json:"signature"`
	EncryptedSymmetricKey string `json:"encrypted_symmetric_key"`
}

func DownloadMessage(messageID int) (*DownloadResult, error) {
	resp, err := authorizedRequest("GET", fmt.Sprintf("/mailbox/download/%d", messageID), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("messaggio %d non trovato", messageID)
	}

	var result DownloadResult
	json.NewDecoder(resp.Body).Decode(&result)
	return &result, nil
}

func Login(username, password string) (string, error) {
	body := map[string]string{"username": username, "password": password}
	data, _ := json.Marshal(body)

	resp, err := http.Post(baseURL+"/login", "application/json", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("credenziali non valide")
	}

	var result struct {
		Token string `json:"token"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.Token, nil
}

func Logout() error {
	resp, err := authorizedRequest("POST", "/logout", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("errore durante il logout")
	}
	return nil
}

type RegisterRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	PublicKey string `json:"public_key"`
}

func Register(username, password, publicKeyB64 string) error {
	body := RegisterRequest{
		Username:  username,
		Password:  password,
		PublicKey: publicKeyB64,
	}
	data, _ := json.Marshal(body)

	resp, err := http.Post(baseURL+"/register", "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s", string(respBody))
	}
	return nil
}
