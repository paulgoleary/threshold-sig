package tecdsa

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"testing"
	)

func TestProtocolBasics(t *testing.T) {

	testKey, err := MakeEthKey()
	require.NoError(t, err)

	p1Proto := NewEthProtocol()
	p2Proto := NewEthProtocol()

	k1, k2, err := p1Proto.MakeKeyShares(testKey.D)
	require.NoError(t, err)

	ckey, sessionID, sessionPK, err := p1Proto.InitP1Session(k1)
	require.NoError(t, err)

	err = p2Proto.InitP2Session(k2, ckey, sessionID, sessionPK)
	require.NoError(t, err)

	p1SignX, err := p1Proto.P1M1()
	require.NoError(t, err)

	msgHash := crypto.Keccak256([]byte("this is the message"))

	p2SignX, c3, err := p2Proto.P2M1(p1SignX, msgHash)
	require.NoError(t, err)

	r, s, err := p1Proto.P1Gen(p2SignX, c3, msgHash)
	require.NoError(t, err)

	pkECDSA := ecdsa.PublicKey{testKey.Curve, testKey.X, testKey.Y}
	verify := ecdsa.Verify(&pkECDSA, msgHash, r, s)
	require.True(t, verify, fmt.Sprintf("multi-party signature did not verify correctly: %v, %v", r, s))
}
