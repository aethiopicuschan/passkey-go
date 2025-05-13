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

// memoryStore is an in-memory credential store.
// It maps credential IDs to public keys and their latest signCount values.
type memoryStore struct {
	mu sync.Mutex
	db map[string]struct {
		Key       *passkey.PublicKeyRecord
		SignCount uint32
	}
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		db: make(map[string]struct {
			Key       *passkey.PublicKeyRecord
			SignCount uint32
		}),
	}
}

// StoreCredential saves a public key and signCount for a given credential.
func (m *memoryStore) StoreCredential(userID, credID string, pubKey *passkey.PublicKeyRecord, signCount uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.db[credID] = struct {
		Key       *passkey.PublicKeyRecord
		SignCount uint32
	}{Key: pubKey, SignCount: signCount}
	return nil
}

// LookupCredential retrieves a public key and signCount using the credential ID.
func (m *memoryStore) LookupCredential(credID string) (*passkey.PublicKeyRecord, uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.db[credID]
	if !ok {
		return nil, 0, fmt.Errorf("not found")
	}
	return rec.Key, rec.SignCount, nil
}

// UpdateSignCount overwrites the signCount for an existing credential.
func (m *memoryStore) UpdateSignCount(credID string, newCount uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec := m.db[credID]
	rec.SignCount = newCount
	m.db[credID] = rec
	return nil
}

var store = newMemoryStore()

// challengeStore holds the issued challenge for each userID (during register/login flow).
var challengeStore = struct {
	mu  sync.Mutex
	val map[string]string // map[userID] => challenge
}{val: make(map[string]string)}

// handleRegisterFinish receives the attestation response from the client,
// extracts and stores the credential public key and signCount.
func handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	type Req struct {
		Attestation string `json:"attestation"` // base64url-encoded attestation object
		UserID      string `json:"user_id"`     // arbitrary user ID
	}
	var req Req
	json.Unmarshal(body, &req)

	// Decode and parse attestationObject
	att, err := passkey.ParseAttestationObject(req.Attestation)
	if err != nil {
		handlePasskeyError(w, err)
		return
	}

	// Extract raw authenticator data (authData)
	auth, err := passkey.ParseAuthData(att.AuthData)
	if err != nil {
		handlePasskeyError(w, err)
		return
	}

	// Convert COSE-encoded public key into Go's ECDSA format
	pubKey, err := passkey.ConvertCOSEKeyToECDSA(auth.PublicKey)
	if err != nil {
		handlePasskeyError(w, err)
		return
	}

	// Store the credential in memory
	record := &passkey.PublicKeyRecord{Key: pubKey}
	credID := base64.RawURLEncoding.EncodeToString(auth.CredID)
	store.StoreCredential(req.UserID, credID, record, auth.SignCount)

	w.Write([]byte("registration OK"))
}

// handleLoginFinish verifies the client's assertion and completes login.
func handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)

	var parsed struct {
		RawID  string `json:"rawId"`   // base64url-encoded credential ID
		UserID string `json:"user_id"` // user identifier
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// Retrieve stored public key and signCount by credential ID
	pubKey, signCount, err := store.LookupCredential(parsed.RawID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Retrieve the previously issued challenge for this user
	challengeStore.mu.Lock()
	expectedChallenge := challengeStore.val[parsed.UserID]
	challengeStore.mu.Unlock()

	// Perform high-level passkey assertion verification
	// Includes signature check, origin/rp/challenge matching, and signCount replay protection
	newCount, err := passkey.VerifyAssertion(
		body,
		"http://localhost:8080", // expected origin
		"localhost",             // expected relying party ID
		expectedChallenge,       // previously issued challenge
		signCount,               // stored signCount
		pubKey.Key,              // public key
	)
	if err != nil {
		handlePasskeyError(w, err)
		return
	}

	// Update stored signCount if verification succeeded
	store.UpdateSignCount(parsed.RawID, newCount)

	// Respond with successful login message
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "login OK",
		"user":    parsed.UserID,
	})
}

// handleChallenge issues a new challenge and stores it for the given user.
func handleChallenge(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		http.Error(w, "user_id required", http.StatusBadRequest)
		return
	}

	// Generate secure random challenge
	chal, err := passkey.GenerateChallenge()
	if err != nil {
		handlePasskeyError(w, err)
		return
	}

	// Store challenge associated with this user
	challengeStore.mu.Lock()
	challengeStore.val[userID] = chal
	challengeStore.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"challenge": chal,
	})
}

// handlePasskeyError inspects and logs structured PasskeyError responses.
func handlePasskeyError(w http.ResponseWriter, err error) {
	var perr *passkey.PasskeyError
	if errors.As(err, &perr) {
		http.Error(w, perr.Message, perr.HTTPStatus)
	} else {
		log.Printf("unexpected error: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// main launches the example HTTP server on :8080
func main() {
	http.Handle("/", http.FileServer(http.Dir("./public")))   // Serve static frontend
	http.HandleFunc("/challenge", handleChallenge)            // Issue challenge
	http.HandleFunc("/register/finish", handleRegisterFinish) // Handle attestation
	http.HandleFunc("/login/finish", handleLoginFinish)       // Handle assertion

	log.Println("Example passkey server running on :8080")
	http.ListenAndServe(":8080", nil)
}
