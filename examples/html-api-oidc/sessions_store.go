package main

import (
	"net/http"
	"sync"

	"github.com/theadell/authress"
)

func StoreTokenInCookie(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{
		Name:  "access_token",
		Value: token,
		Path:  "/",
	}
	http.SetCookie(w, cookie)
}

func GetTokenFromCookie(r *http.Request) (string, bool) {
	cookie, err := r.Cookie("access_token")
	if err != nil {
		return "", false
	}
	return cookie.Value, true
}

type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*authress.Claims
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*authress.Claims),
	}
}

func (store *SessionStore) Set(sub string, idToken *authress.Claims) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.sessions[sub] = idToken
}

func (store *SessionStore) Get(sub string) (*authress.Claims, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	idToken, exists := store.sessions[sub]
	return idToken, exists
}

func (store *SessionStore) Delete(sub string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.sessions, sub)
}
