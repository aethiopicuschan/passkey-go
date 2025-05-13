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

// memoryStore is an in-memory database for storing credentials.
// It maps credential IDs to public keys and sign counters.
type memoryStore struct {
	mu sync.Mutex
	db map[string]struct {
		Key       *passkey.PublicKeyRecord
		SignCount uint32
	}
}

// newMemoryStore creates and returns a new memoryStore instance.
func newMemoryStore() *memoryStore {
	return &memoryStore{db: make(map[string]struct {
		Key       *passkey.PublicKeyRecord
		SignCount uint32
	})}
}

// StoreCredential stores the credential data in memory for a given user.
func (m *memoryStore) StoreCredential(userID, credID string, pubKey *passkey.PublicKeyRecord, signCount uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.db[credID] = struct {
		Key       *passkey.PublicKeyRecord
		SignCount uint32
	}{Key: pubKey, SignCount: signCount}
	return nil
}

// LookupCredential retrieves the stored public key and sign count for a given credential ID.
func (m *memoryStore) LookupCredential(credID string) (*passkey.PublicKeyRecord, uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.db[credID]
	if !ok {
		return nil, 0, fmt.Errorf("not found")
	}
	return rec.Key, rec.SignCount, nil
}

// UpdateSignCount updates the sign counter for a given credential ID.
func (m *memoryStore) UpdateSignCount(credID string, newCount uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec := m.db[credID]
	rec.SignCount = newCount
	m.db[credID] = rec
	return nil
}

var store = newMemoryStore()

// challengeStore holds ongoing challenges for each user to verify login/register requests.
var challengeStore = struct {
	mu  sync.Mutex
	val map[string]string // map[userID]challenge
}{val: make(map[string]string)}

// handleRegisterFinish handles the final step of registration.
// It parses the attestation object, extracts the public key, and stores it with sign count.
func handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	type Req struct {
		Attestation string `json:"attestation"`
		UserID      string `json:"user_id"`
	}
	var req Req
	json.Unmarshal(body, &req)

	// Parse the attestation object.
	att, err := passkey.ParseAttestationObject(req.Attestation)
	if err != nil {
		handlePasskeyError(w, err)
		return
	}

	// Parse authenticator data from attestation.
	auth, err := passkey.ParseAuthData(att.AuthData)
	if err != nil {
		handlePasskeyError(w, err)
		return
	}

	// Convert COSE public key format to ECDSA.
	pubKey, err := passkey.ConvertCOSEKeyToECDSA(auth.PublicKey)
	if err != nil {
		handlePasskeyError(w, err)
		return
	}

	// Store the credential information.
	record := &passkey.PublicKeyRecord{Key: pubKey}
	credID := base64.RawURLEncoding.EncodeToString(auth.CredID)
	store.StoreCredential(req.UserID, credID, record, auth.SignCount)

	w.Write([]byte("registration OK"))
}

// handleLoginFinish handles the final step of login.
// It verifies the assertion signature and updates the sign counter.
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

	// Lookup stored credential by ID.
	pubKey, signCount, err := store.LookupCredential(parsed.RawID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Parse the assertion object from request body.
	authData, clientData, sig, err := passkey.ParseAssertion(body)
	if err != nil {
		handlePasskeyError(w, err)
		return
	}

	// Parse client data JSON.
	clientParsed, err := passkey.ParseClientDataJSON(clientData)
	if err != nil {
		handlePasskeyError(w, err)
		return
	}

	// Check that the challenge matches the one stored for this user.
	challengeStore.mu.Lock()
	expected := challengeStore.val[parsed.UserID]
	challengeStore.mu.Unlock()
	if expected != clientParsed.Challenge {
		http.Error(w, "challenge mismatch", http.StatusBadRequest)
		return
	}

	// Verify the assertion signature using the stored public key.
	if err := passkey.VerifyAssertionSignature(authData, clientData, sig, pubKey.Key); err != nil {
		handlePasskeyError(w, err)
		return
	}

	// Parse auth data and verify sign count.
	authParsed, err := passkey.ParseAuthData(authData)
	if err != nil {
		handlePasskeyError(w, err)
		return
	}
	if err := passkey.CheckSignCount(signCount, authParsed.SignCount); err != nil {
		handlePasskeyError(w, err)
		return
	}

	// Update stored sign count after successful login.
	store.UpdateSignCount(parsed.RawID, authParsed.SignCount)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "login OK",
		"user":    parsed.UserID,
	})
}

// handleChallenge generates a challenge and stores it per user.
// This challenge is later verified during login/register.
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

	// Store challenge for this user.
	challengeStore.mu.Lock()
	challengeStore.val[userID] = chal
	challengeStore.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"challenge": chal,
	})
}

// handlePasskeyError returns a proper HTTP response for a PasskeyError or logs unexpected ones.
func handlePasskeyError(w http.ResponseWriter, err error) {
	var perr *passkey.PasskeyError
	if errors.As(err, &perr) {
		http.Error(w, perr.Message, perr.HTTPStatus)
	} else {
		log.Printf("unexpected error: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// main sets up the HTTP server and routes for the passkey example.
func main() {
	http.Handle("/", http.FileServer(http.Dir("./public")))
	http.HandleFunc("/challenge", handleChallenge)
	http.HandleFunc("/register/finish", handleRegisterFinish)
	http.HandleFunc("/login/finish", handleLoginFinish)

	log.Println("Example passkey server running on :8080")
	http.ListenAndServe(":8080", nil)
}
