package session

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"sort"
)

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWKSProvider interface {
	PublicJWKS() (JWKS, error)
}

func (m *Manager) PublicJWKS() (JWKS, error) {
	if len(m.publicKeys) == 0 {
		return JWKS{}, errors.New("no public keys available")
	}

	keys := make([]string, 0, len(m.publicKeys))
	for kid := range m.publicKeys {
		keys = append(keys, kid)
	}
	sort.Strings(keys)

	out := JWKS{Keys: make([]JWK, 0, len(keys))}
	for _, kid := range keys {
		pub := m.publicKeys[kid]
		out.Keys = append(out.Keys, rsaPublicJWK(kid, pub))
	}
	return out, nil
}

func rsaPublicJWK(kid string, pub *rsa.PublicKey) JWK {
	return JWK{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}
