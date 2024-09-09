package authress

import (
	"context"
	"crypto"
	"fmt"
	"strconv"

	"github.com/MicahParks/jwkset"
)

type JWKSStore interface {
	GetKey(ctx context.Context, kid string) (crypto.PublicKey, error)
}

type inMemoryStore struct {
	set jwkset.Storage
}

func (s *inMemoryStore) GetKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	key, err := s.set.KeyRead(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("key not found for kid %s", kid)
	}
	return key.Key(), err
}

type testMemoryStore struct {
	set map[string]crypto.PublicKey
}

func (s *testMemoryStore) GetKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	key, ok := s.set[kid]
	if !ok {
		return nil, fmt.Errorf("key not found for kid %s", kid)
	}
	return key, nil
}

func newTestStore(keys ...crypto.PublicKey) *testMemoryStore {
	set := make(map[string]crypto.PublicKey)
	for i, v := range keys {
		set[strconv.Itoa(i)] = v
	}
	return &testMemoryStore{set: set}
}
