package research

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/paulgoleary/cloud-sigman/tecdsa"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func TestECIESThreshold(t *testing.T) {

	Zq := ecies.DefaultCurve.Params().N

	sk, err := ecies.GenerateKey(rand.Reader, ecies.DefaultCurve, ecies.ECIES_AES128_SHA256)
	require.NoError(t, err)

	// generate multiplicative key shares x1, x2
	x1 := tecdsa.MakeRandoIntWithOrder(Zq)

	x2 := new(big.Int).ModInverse(x1, Zq)
	x2.Mul(x2, sk.D)
	x2.Mod(x2, Zq)

	checkX := new(big.Int).Mul(x1, x2)
	checkX.Mod(checkX, Zq)

	if sk.D.Cmp(checkX) != 0 {
		t.Errorf("x1 and x2 should be multiplicative shares of x: %v, %v", x1, x2)
	}

	testData := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	encData, err := ecies.Encrypt(rand.Reader, &sk.PublicKey, testData, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, encData)

	sk = nil // nothing up our sleeve - 'forget' initial secret key

	// output is [65 bytes generated key][20 bytes sym encryption][32 bytes tag]
	// where sym encryption is [16 bytes IV][enc bytes] - don't think an IV is really necessary here...
	// also, enc point is not compressed...

	encX, encY :=  elliptic.Unmarshal(ecies.DefaultCurve, encData[:65])
	require.True(t, ecies.DefaultCurve.IsOnCurve(encX, encY), "trivial test")

	// apply x1 to encryption key
	x1EncX, x1EncY := ecies.DefaultCurve.ScalarMult(encX, encY, x1.Bytes())
	partialKeyBytes := elliptic.Marshal(ecies.DefaultCurve, x1EncX, x1EncY)
	// re-constitute encryption package with partially-applied (x1) key share
	partialEncData := append(partialKeyBytes, encData[65:]...)

	// create full key from x2 key share
	pkX2X, pkX2Y := ecies.DefaultCurve.ScalarBaseMult(x2.Bytes())
	require.NoError(t, err)
	skX2 := ecies.PrivateKey{D: x2, PublicKey: ecies.PublicKey{Curve: ecies.DefaultCurve, X: pkX2X, Y: pkX2Y, Params: sk.Params}}

	// apply x2 keyshare to decrypt
	testDec, err := skX2.Decrypt(partialEncData, nil, nil)
	require.NoError(t, err)
	require.True(t, bytes.Compare(testData, testDec) == 0, "threshold ECIES seems pretty easy!")
}