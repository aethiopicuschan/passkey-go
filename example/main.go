package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/aethiopicuschan/passkey-go"
	"golang.org/x/crypto/bcrypt"
)

// User represents an individual user with basic profile and authentication information.
type User struct {
	ID           string
	Email        string
	Name         string
	PasswordHash []byte // bcrypt-hashed password
}

// Users is a collection of User objects.
type Users []User

// GetByUserID returns a user matching the given user ID.
func (u *Users) GetByUserID(userID string) *User {
	for _, user := range *u {
		if user.ID == userID {
			return &user // Found user
		}
	}
	return nil // Not found
}

// In-memory user store
var userStore Users

// Session represents an active user session, identified by a session key.
type Session struct {
	SessionKey string
	UserID     string
}

// Sessions is a collection of Session objects.
type Sessions []Session

// GetBySessionKey looks up a session by its key.
func (s *Sessions) GetBySessionKey(sessionKey string) *Session {
	for _, session := range *s {
		if session.SessionKey == sessionKey {
			return &session // Found session
		}
	}
	return nil // Not found
}

// DeleteBySessionKey removes a session from memory based on its key.
func (s *Sessions) DeleteBySessionKey(sessionKey string) {
	for i, session := range *s {
		if session.SessionKey == sessionKey {
			// Remove the session from the slice
			*s = slices.Delete(*s, i, i+1)
			return
		}
	}
}

// In-memory session store
var sessionStore Sessions

// challengeStore holds temporary passkey challenges indexed by a unique key.
// This map is protected by a mutex to handle concurrent access safely.
var challengeStore = struct {
	mu  sync.Mutex
	val map[string]string
}{val: make(map[string]string)}

// Passkey represents a registered WebAuthn credential tied to a user.
type Passkey struct {
	CredentialID string
	UserID       string
	PublicKey    []byte
	SignCount    uint32
}

// Passkeys is a collection of registered Passkeys.
type Passkeys []Passkey

// In-memory passkey store
var passkeyStore Passkeys

// LookupCredential finds a passkey's public key and sign count based on its credential ID.
func (p *Passkeys) LookupCredential(credID string) ([]byte, uint32, error) {
	for _, passkey := range *p {
		if passkey.CredentialID == credID {
			return passkey.PublicKey, passkey.SignCount, nil // Return match
		}
	}
	return nil, 0, errors.New("credential not found")
}

// UpdateSignCount updates the sign counter for a specific passkey.
func (p *Passkeys) UpdateSignCount(credID string, newSignCount uint32) error {
	for i, passkey := range *p {
		if passkey.CredentialID == credID {
			(*p)[i].SignCount = newSignCount // Overwrite old sign count
			return nil
		}
	}
	return errors.New("credential not found")
}

// GetUserID returns the user ID associated with a given credential ID.
func (p *Passkeys) GetUserID(credID string) (string, error) {
	for _, passkey := range *p {
		if passkey.CredentialID == credID {
			return passkey.UserID, nil
		}
	}
	return "", errors.New("credential not found")
}

// init initializes the user store with two sample users and hashed passwords.
func init() {
	// Hash the password "password" using bcrypt
	ph, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)

	// Create sample users "bob" and "alice" with the same password
	userStore = Users{
		{ID: "1", Email: "bob@example.com", Name: "bob", PasswordHash: ph},
		{ID: "2", Email: "alice@example.com", Name: "alice", PasswordHash: ph},
	}
}

// GenerateRandomKey creates a short random key using crypto/rand and fallback to non-secure fallback.
func GenerateRandomKey() string {
	return rand.Text() // NOT cryptographically secure; for demo only
}

// CreateSession creates a session for a given user ID and returns a Session and corresponding cookie.
func CreateSession(userID string) (Session, *http.Cookie) {
	// Generate a session key based on userID (insecure: should use UUID or crypto/rand in production)
	sessionKey := "session_" + userID

	// Construct a new session object
	session := Session{
		SessionKey: sessionKey,
		UserID:     userID,
	}

	// Create a secure session cookie
	cookie := &http.Cookie{
		Name:     "session_key",
		Value:    sessionKey,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour), // Valid for 24 hours
		HttpOnly: true,                           // Prevent access via JavaScript
		Secure:   true,                           // Ensure HTTPS-only
		SameSite: http.SameSiteStrictMode,        // Prevent CSRF in cross-origin requests
	}

	return session, cookie
}

// LoginHandler processes email/password login and issues a session cookie.
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	type LoginRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	// Ensure the request method is POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the request body as JSON into LoginRequest
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Search for user by email
	for _, user := range userStore {
		if user.Email == req.Email {
			// Compare submitted password with stored bcrypt hash
			if err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(req.Password)); err != nil {
				http.Error(w, "Invalid credentials", http.StatusUnauthorized)
				return
			}

			// Create new session and set it in cookie
			session, cookie := CreateSession(user.ID)
			sessionStore = append(sessionStore, session)
			http.SetCookie(w, cookie)
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	// If no matching email found, return 404
	http.Error(w, "User not found", http.StatusNotFound)
}

// LogoutHandler deletes the session associated with the current session cookie.
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Retrieve session cookie
	cookie, err := r.Cookie("session_key")
	if err != nil || cookie.Value == "" {
		// Nothing to do if no cookie is found
		w.WriteHeader(http.StatusOK)
		return
	}

	// Delete session from store
	sessionStore.DeleteBySessionKey(cookie.Value)
	w.WriteHeader(http.StatusOK)
}

// GetMeHandler returns the current authenticated user's profile info.
func GetMeHandler(w http.ResponseWriter, r *http.Request) {
	type GetMeResponse struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get session cookie
	cookie, err := r.Cookie("session_key")
	if err != nil || cookie.Value == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Look up session from cookie value
	session := sessionStore.GetBySessionKey(cookie.Value)
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Look up user associated with session
	user := userStore.GetByUserID(session.UserID)
	if user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Encode user data as JSON and respond
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(GetMeResponse{
		ID:    user.ID,
		Email: user.Email,
		Name:  user.Name,
	}); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// GetChallenge generates a random passkey challenge and stores it by key.
func GetChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Generate a challenge string (random 32 bytes base64url)
	chal, err := passkey.GenerateChallenge()
	if err != nil {
		handlePasskeyError(w, err)
		return
	}

	// Store the challenge using a random key
	key := GenerateRandomKey()
	challengeStore.mu.Lock()
	challengeStore.val[key] = chal
	challengeStore.mu.Unlock()

	// Return both the key and challenge string as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"key":   key,
		"value": chal,
	})
}

// RegisterPasskeyHandler accepts a WebAuthn attestation and stores a new credential.
func RegisterPasskeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate session from cookie
	cookie, err := r.Cookie("session_key")
	if err != nil || cookie.Value == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	session := sessionStore.GetBySessionKey(cookie.Value)
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	user := userStore.GetByUserID(session.UserID)
	if user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Read request body
	body, _ := io.ReadAll(r.Body)
	var req struct {
		Attestation string `json:"attestation"` // base64url-encoded attestation
	}
	json.Unmarshal(body, &req)

	// Parse and decode attestation object
	att, err := passkey.ParseAttestationObject(req.Attestation)
	if err != nil {
		handlePasskeyError(w, err)
		return
	}

	// Extract authenticator data from attestation
	auth, err := passkey.ParseAuthData(att.AuthData)
	if err != nil {
		handlePasskeyError(w, err)
		return
	}

	// Convert COSE-encoded key to Go ECDSA format
	pubKey, err := passkey.ConvertCOSEKeyToECDSA(auth.PublicKey)
	if err != nil {
		handlePasskeyError(w, err)
		return
	}

	// Marshal public key to store as []byte
	record := &passkey.PublicKeyRecord{Key: pubKey}
	rb, err := passkey.MarshalPublicKey(*record)
	if err != nil {
		handlePasskeyError(w, err)
		return
	}

	// Store new passkey in memory
	credID := base64.RawURLEncoding.EncodeToString(auth.CredID)
	passkeyStore = append(passkeyStore, Passkey{
		CredentialID: credID,
		UserID:       user.ID,
		PublicKey:    rb,
		SignCount:    auth.SignCount,
	})

	w.WriteHeader(http.StatusOK)
}

// LoginWithPasskeyHandler verifies an assertion and creates a session on success.
func LoginWithPasskeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	body, _ := io.ReadAll(r.Body)
	var parsed struct {
		Cred string `json:"cred"` // base64url-encoded assertion
		Key  string `json:"key"`  // key to lookup challenge
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// Decode base64 credential
	decoded, err := base64.RawURLEncoding.DecodeString(parsed.Cred)
	if err != nil {
		http.Error(w, "invalid credential encoding", http.StatusBadRequest)
		return
	}

	// Parse assertion
	assertion, err := passkey.ParseAssertion(decoded)
	if err != nil {
		handlePasskeyError(w, err)
		return
	}

	credID := assertion.Raw.RawID

	// Look up stored credential by ID
	pkrec, sc, err := passkeyStore.LookupCredential(credID)
	if err != nil {
		http.Error(w, "credential not found", http.StatusBadRequest)
		return
	}

	// Decode stored public key
	pk, err := passkey.UnmarshalPublicKey(pkrec)
	if err != nil {
		return
	}

	// Get expected challenge from store
	challengeStore.mu.Lock()
	expectedChallenge := challengeStore.val[parsed.Key]
	challengeStore.mu.Unlock()

	// Perform full WebAuthn assertion verification
	newCount, err := passkey.VerifyAssertion(
		decoded,
		"http://localhost:8080", // expected origin
		"localhost",             // relying party ID
		expectedChallenge,       // challenge originally issued
		sc,                      // previous sign count
		pk.Key,                  // public key
	)
	if err != nil {
		handlePasskeyError(w, err)
		return
	}

	// Update sign count in memory
	err = passkeyStore.UpdateSignCount(credID, newCount)
	if err != nil {
		http.Error(w, "failed to update sign count", http.StatusInternalServerError)
		return
	}

	// Create session and issue session cookie
	userID, err := passkeyStore.GetUserID(credID)
	if err != nil {
		http.Error(w, "credential not found", http.StatusBadRequest)
		return
	}
	session, cookie := CreateSession(userID)
	sessionStore = append(sessionStore, session)
	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusOK)
}

// handlePasskeyError standardizes error responses from the passkey library.
func handlePasskeyError(w http.ResponseWriter, err error) {
	var perr *passkey.PasskeyError
	if errors.As(err, &perr) {
		// If it's a PasskeyError, return its structured message and status
		http.Error(w, perr.Message, perr.HTTPStatus)
	} else {
		// Otherwise return a generic error
		log.Printf("unexpected error: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// main starts the HTTP server and registers all routes.
func main() {
	// Serve static frontend files from ./public directory
	http.Handle("/", http.FileServer(http.Dir("./public")))

	// Register each backend API handler
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/logout", LogoutHandler)
	http.HandleFunc("/me", GetMeHandler)
	http.HandleFunc("/passkey/challenge", GetChallenge)
	http.HandleFunc("/passkey/register", RegisterPasskeyHandler)
	http.HandleFunc("/passkey/login", LoginWithPasskeyHandler)

	log.Println("Server started on :8080")

	// Start HTTP server on port 8080
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
