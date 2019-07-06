package tecdsa

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"log"
	"testing"
	"time"
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

	start := time.Now()

	iterations := int64(1000)
	for i := int64(0); i < iterations; i++ {

		if i > 0 && i % 100 == 0 {
			log.Printf("at iteration %v\n", i)
		}

		p1SignX, err := p1Proto.P1M1()
		require.NoError(t, err)
		require.Nil(t, p1SignX.Rx, "proof should be generated and returned without R1")
		require.Nil(t, p1SignX.Ry)

		require.Equal(t, i * 2 + 1, p1Proto.getSessionOrd())

		p2SignX, err := p2Proto.P2M1(p1SignX)
		require.NoError(t, err)

		require.Equal(t, i * 2 + 2, p2Proto.getSessionOrd())

		p1SignX, err = p1Proto.P1M2(p2SignX)
		require.NoError(t, err)
		require.NotNil(t, p1SignX.Rx, "p1 now 'de-commits' - sends R1")
		require.NotNil(t, p1SignX.Ry)

		msgHash := crypto.Keccak256([]byte("this is the message"))

		c3, err := p2Proto.P2M2(p1SignX, msgHash)
		require.NoError(t, err)

		r, s, err := p1Proto.P1Gen(c3, msgHash)
		require.NoError(t, err)

		pkECDSA := ecdsa.PublicKey{testKey.Curve, testKey.X, testKey.Y}
		verify := ecdsa.Verify(&pkECDSA, msgHash, r, s)
		require.True(t, verify, fmt.Sprintf("multi-party signature did not verify correctly: %v, %v", r, s))
	}

	elapsed := time.Since(start)
	log.Printf("total time %v, average millis %v", elapsed, elapsed.Nanoseconds() / iterations / 1000000)

}
