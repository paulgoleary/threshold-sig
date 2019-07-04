package tecdsa

import (
	"crypto/ecdsa"
	rand2 "crypto/rand"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"golang.org/x/crypto/sha3"
	"hash"
)

func NewEthProtocol() *TPTDProtocol {
	hasherFunc := func() hash.Hash {
		return sha3.NewLegacyKeccak256()
	}
	return NewProtocol(secp256k1.S256(), hasherFunc)
}

func MakeEthKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(secp256k1.S256(), rand2.Reader)
}
