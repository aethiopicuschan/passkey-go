package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"

	"github.com/aethiopicuschan/passkey-go"
)

type memoryStore struct {
	mu sync.Mutex
	db map[string]struct {
		Key       *passkey.PublicKeyRecord
		SignCount uint32
	}
}

func newMemoryStore() *memoryStore {
	return &memoryStore{db: make(map[string]struct {
		Key       *passkey.PublicKeyRecord
		SignCount uint32
	})}
}

func (m *memoryStore) StoreCredential(userID, credID string, pubKey *passkey.PublicKeyRecord, signCount uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.db[credID] = struct {
		Key       *passkey.PublicKeyRecord
		SignCount uint32
	}{Key: pubKey, SignCount: signCount}
	return nil
}

func (m *memoryStore) LookupCredential(credID string) (*passkey.PublicKeyRecord, uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.db[credID]
	if !ok {
		return nil, 0, fmt.Errorf("not found")
	}
	return rec.Key, rec.SignCount, nil
}

func (m *memoryStore) UpdateSignCount(credID string, newCount uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec := m.db[credID]
	rec.SignCount = newCount
	m.db[credID] = rec
	return nil
}

var store = newMemoryStore()

var challengeStore = struct {
	mu  sync.Mutex
	val map[string]string // map[userID]challenge
}{val: make(map[string]string)}

func handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	type Req struct {
		Attestation string `json:"attestation"`
		UserID      string `json:"user_id"`
	}
	var req Req
	json.Unmarshal(body, &req)

	att, err := passkey.ParseAttestationObject(req.Attestation)
	if err != nil {
		handlePasskeyError(w, err)
		return
	}
	auth, err := passkey.ParseAuthData(att.AuthData)
	if err != nil {
		handlePasskeyError(w, err)
		return
	}
	pubKey, err := passkey.ConvertCOSEKeyToECDSA(auth.PublicKey)
	if err != nil {
		handlePasskeyError(w, err)
		return
	}
	record := &passkey.PublicKeyRecord{Key: pubKey}
	credID := base64.RawURLEncoding.EncodeToString(auth.CredID)
	store.StoreCredential(req.UserID, credID, record, auth.SignCount)
	w.Write([]byte("registration OK"))
}

func handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)

	var parsed struct {
		RawID  string `json:"rawId"`
		UserID string `json:"user_id"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	pubKey, signCount, err := store.LookupCredential(parsed.RawID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	authData, clientData, sig, err := passkey.ParseAssertion(body)
	if err != nil {
		handlePasskeyError(w, err)
		return
	}

	clientParsed, err := passkey.ParseClientDataJSON(clientData)
	if err != nil {
		handlePasskeyError(w, err)
		return
	}

	challengeStore.mu.Lock()
	expected := challengeStore.val[parsed.UserID]
	challengeStore.mu.Unlock()
	if expected != clientParsed.Challenge {
		http.Error(w, "challenge mismatch", http.StatusBadRequest)
		return
	}

	if err := passkey.VerifyAssertionSignature(authData, clientData, sig, pubKey.Key); err != nil {
		handlePasskeyError(w, err)
		return
	}
	authParsed, err := passkey.ParseAuthData(authData)
	if err != nil {
		handlePasskeyError(w, err)
		return
	}
	if err := passkey.CheckSignCount(signCount, authParsed.SignCount); err != nil {
		handlePasskeyError(w, err)
		return
	}
	store.UpdateSignCount(parsed.RawID, authParsed.SignCount)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "login OK",
		"user":    parsed.UserID,
	})
}

func handleChallenge(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		http.Error(w, "user_id required", http.StatusBadRequest)
		return
	}
	chal, err := passkey.GenerateChallenge()
	if err != nil {
		handlePasskeyError(w, err)
		return
	}
	challengeStore.mu.Lock()
	challengeStore.val[userID] = chal
	challengeStore.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"challenge": chal,
	})
}

func handlePasskeyError(w http.ResponseWriter, err error) {
	var perr *passkey.PasskeyError
	if errors.As(err, &perr) {
		http.Error(w, perr.Message, perr.HTTPStatus)
	} else {
		log.Printf("unexpected error: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func main() {
	http.Handle("/", http.FileServer(http.Dir("./public")))
	http.HandleFunc("/challenge", handleChallenge)
	http.HandleFunc("/register/finish", handleRegisterFinish)
	http.HandleFunc("/login/finish", handleLoginFinish)
	log.Println("Example passkey server running on :8080")
	http.ListenAndServe(":8080", nil)
}
