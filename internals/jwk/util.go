package jwk

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
)

func JWKToRSA(nB64url, eB64url string) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(nB64url)
	if err != nil {
		return nil, err
	}

	eb, err := base64.RawURLEncoding.DecodeString(eB64url)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nb)

	var e int
	for _, b := range eb {
		e = e<<8 | int(b)
	}

	if e == 0 {
		return nil, errors.New("invalid exponent")
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}
