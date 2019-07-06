package research

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/paulgoleary/cloud-sigman/tecdsa"
	"github.com/roasbeef/go-go-gadget-paillier"
	"math/big"
	"testing"
)

var ZERO = new(big.Int).SetInt64(0)

// adapted from https://play.golang.org/p/SmzvkDjYlb
// greatest common divisor (GCD) via Euclidean algorithm
// TODO: hey, big.Int has GCD already ...
func GCD(a, b *big.Int) *big.Int {

	for b.Cmp(ZERO) != 0 {
		t := new(big.Int).Set(b)
		b = new(big.Int).Mod(a, b)
		a = t
	}
	return a
}

// find Least Common Multiple (LCM) via GCD
func LCM(a, b *big.Int, integers ...*big.Int) *big.Int {
	result := new(big.Int).Mul(a, b)
	result = result.Div(result, GCD(a, b))

	for i := 0; i < len(integers); i++ {
		result = LCM(result, integers[i])
	}

	return result
}

// TODO: minimum key length is considered comparable to RSA, so currently 2048

// TODO: i would like to write some tests that this system is set up correctly. i assume that the aspects of implementation that
//  deviate from the specification are due to optimizations that don't diminish the security of the system but it would be nice
//  to know that for myself ...
// from: https://en.wikipedia.org/wiki/Paillier_cryptosystem
// Choose two large prime numbers p and q randomly and independently of each other such that {gcd(pq, (p-1)(q-1)) = 1.
// This property is assured if both primes are of equal length.[1]
// Compute n = pq and lambda = lcm(p - 1, q - 1) {\displaystyle \lambda =\operatorname {lcm} (p-1,q-1)} \lambda =\operatorname {lcm}(p-1,q-1). lcm means Least Common Multiple.
//  etc.

// TODO, from README: Warning this library was created primarily for education purposes, with future application for a course project. You should NOT USE THIS CODE IN PRODUCTION SYSTEMS.
func TestPaillierBasics(t *testing.T) {
	// Generate a 128-bit private key.
	privKey, _ := paillier.GenerateKey(rand.Reader, 128)

	// Encrypt the number "15".
	m15 := new(big.Int).SetInt64(15)
	c15, _ := paillier.Encrypt(&privKey.PublicKey, m15.Bytes())

	// Decrypt the number "15".
	d, _ := paillier.Decrypt(privKey, c15)
	plainText := new(big.Int).SetBytes(d)
	fmt.Println("Decryption Result of 15: ", plainText.String()) // 15

	// Now for the fun stuff.

	// Encrypt the number "20".
	m20 := new(big.Int).SetInt64(20)
	c20, _ := paillier.Encrypt(&privKey.PublicKey, m20.Bytes())

	// Add the encrypted integers 15 and 20 together.
	plusM16M20 := paillier.AddCipher(&privKey.PublicKey, c15, c20)
	decryptedAddition, _ := paillier.Decrypt(privKey, plusM16M20)
	fmt.Println("Result of 15+20 after decryption: ",
		new(big.Int).SetBytes(decryptedAddition).String()) // 35!

	// Add the encrypted integer 15 to plaintext constant 10.
	plusE15and10 := paillier.Add(&privKey.PublicKey, c15, new(big.Int).SetInt64(10).Bytes())
	decryptedAddition, _ = paillier.Decrypt(privKey, plusE15and10)
	fmt.Println("Result of 15+10 after decryption: ",
		new(big.Int).SetBytes(decryptedAddition).String()) // 25!

	// Multiply the encrypted integer 15 by the plaintext constant 10.
	mulE15and10 := paillier.Mul(&privKey.PublicKey, c15, new(big.Int).SetInt64(10).Bytes())
	decryptedMul, _ := paillier.Decrypt(privKey, mulE15and10)
	fmt.Println("Result of 15*10 after decryption: ",
		new(big.Int).SetBytes(decryptedMul).String()) // 150!
}

func TestSimpleHomomorphs(t *testing.T) {

	ahsPrivKeyAlice, _ := paillier.GenerateKey(rand.Reader, 128)

	Zq := int64(251)

	a := int64(17)
	b := int64(19)

	abMul := (a * b) % Zq

	cA, _ := paillier.Encrypt(&ahsPrivKeyAlice.PublicKey, new(big.Int).SetInt64(a).Bytes())

	cAb := paillier.Mul(&ahsPrivKeyAlice.PublicKey, cA, new(big.Int).SetInt64(b).Bytes())

	betaPrime := int64(1000)

	cB := paillier.Add(&ahsPrivKeyAlice.PublicKey, cAb, new(big.Int).SetInt64(betaPrime).Bytes())

	// β = −β′ mod q
	beta := new(big.Int).SetInt64(-betaPrime)
	beta.Mod(beta, new(big.Int).SetInt64(Zq))

	decAlphaPrime, _ := paillier.Decrypt(ahsPrivKeyAlice, cB)
	alphaPrime := new(big.Int).SetBytes(decAlphaPrime)
	alpha := alphaPrime.Mod(alphaPrime, new(big.Int).SetInt64(Zq))

	abAdd := alpha.Add(alpha, beta)
	abAdd.Mod(abAdd, new(big.Int).SetInt64(Zq))
	if abAdd.Cmp(new(big.Int).SetInt64(abMul)) != 0 {
		t.Errorf("simple homomorphism checks failed: got (alpha + beta) mod Zq, (a * b) mod Zq: %v, %v", abAdd, abMul)
	}
}

// from http://stevengoldfeder.com/papers/GG18.pdf, section 3
func TestShareConversion(t *testing.T) {

	// let's assume secp256k1 so our system's Zq will be the order of the curve
	Zq := secp256k1.S256().N

	privAlice, _ := ecies.GenerateKey(rand.Reader, secp256k1.S256(), nil)
	privBob, _ := ecies.GenerateKey(rand.Reader, secp256k1.S256(), nil)

	a := privAlice.D
	b := privBob.D

	checkAB := new(big.Int).Mul(a, b)
	checkAB.Mod(checkAB, Zq)

	// ahs for 'additive homomorphic scheme'
	ahsPrivKeyAlice, _ := paillier.GenerateKey(rand.Reader, 2048)

	/*
	(1) Alice initiates the protocol by
		• sending cA = EA(a) to Bob
		• proving in ZK that a < K via a range proof  TODO?
	 */
	 cA, _ := paillier.Encrypt(&ahsPrivKeyAlice.PublicKey, a.Bytes())

	 /*
	 (2) Bob computes the ciphertext cB = b ×E cA +E EA(β′) = EA(ab + β′) where β′ is chosen uniformly at random in ZN.
		Bob sets his share to β = −β′ mod q. He responds to Alice by
			• sending cB
			• proving in ZK that b < K  TODO?
			• only if B = g^b is public proving in ZK that he knows b, β′ such that B = g^b and cB = b ×E cA +E EA(β′)  TODO?
	  */
	  // β′ is chosen uniformly at random in ZN


	// cAb = b ×E cA
	cAb := paillier.Mul(&ahsPrivKeyAlice.PublicKey, cA, b.Bytes())

	cAbCheckBytes, _ := paillier.Decrypt(ahsPrivKeyAlice, cAb)
	cAbCheck := new(big.Int).SetBytes(cAbCheckBytes)
	cAbCheck.Mod(cAbCheck, Zq)
	if checkAB.Cmp(cAbCheck) != 0 {
		t.Errorf("homomorphic multiplication of cA and b failed, expect %v, got %v", checkAB, cAbCheck)
	}

	betaPrime := tecdsa.MakeRandoIntWithOrder(ahsPrivKeyAlice.N)

	// cB = Ea(ab + β′)
	cB := paillier.Add(&ahsPrivKeyAlice.PublicKey, cAb, betaPrime.Bytes())

	// β = −β′ mod q
	betaBob := new(big.Int).SetBytes(betaPrime.Bytes())
	betaBob.Neg(betaBob)
	betaBob.Mod(betaBob, Zq)

	// (3) Alice decrypts cB to obtain α′ and sets α = α′ mod q
	decAlphaPrime, _ := paillier.Decrypt(ahsPrivKeyAlice, cB)
	alphaAlice := new(big.Int).SetBytes(decAlphaPrime)
	alphaAlice.Mod(alphaAlice, Zq)

	checkAlphaBeta := new(big.Int).Add(alphaAlice, betaBob)
	checkAlphaBeta.Mod(checkAlphaBeta, Zq)

	if checkAB.Cmp(checkAlphaBeta) != 0 {
		t.Errorf("alpha and beta should be additive shares of a * b mod Zq, got %v and %v", checkAB, checkAlphaBeta)
	}
}

// TODO: move? not related to Paillier ...
func TestEthereumECDSA(t *testing.T) {
	randoBytes := make([]byte, 32)
	rand.Read(randoBytes)
	testKey, _ := crypto.ToECDSA(randoBytes)
	println(testKey)
}

func TestTwoPartyECDSA(t *testing.T) {

	theCurve := secp256k1.S256()
	Zq := theCurve.N

	privAlice, _ := ecies.GenerateKey(rand.Reader, theCurve, nil)

	// in the protocol i want to simulate we assume:
	// . alice has an existing public + private key pair
	// . alice acts as a trusted dealer and creates multiplicative shares of the private key x - which we call x1, x2
	x1 := tecdsa.MakeRandoIntWithOrder(Zq)

	x2 := new(big.Int).ModInverse(x1, Zq)
	x2.Mul(x2, privAlice.D)
	x2.Mod(x2, Zq)

	checkX := new(big.Int).Mul(x1, x2)
	checkX.Mod(checkX, Zq)

	if privAlice.D.Cmp(checkX) != 0 {
		t.Errorf("x1 and x2 should be multiplicative shares of x: %v, %v", x1, x2)
	}

	// alice also defines parameters for Paillier encryption - if all goes according to plan only alice's key pair is
	//  necessary. that is, the assumption is that alice's public key is communicated to bob and that is sufficient for the
	//  protocol. further, we want to assume that a fresh set of Paillier parameters is generated for each signing interaction.
	ahsPrivKeyAlice, _ := paillier.GenerateKey(rand.Reader, 2048)

	// following 'Fast Secure Two-Party ECDSA Signing, Yehuda Lindell' - Protocol 3.2, at the start of signing:
	// . alice (P1) has x1 and Q - in this scenario Q is alice's original public key
	// . bob (P2) has x2, Q and Ckey, which is E(x1). in our protocol - i.e. trusted dealer - we will assume that x2
	//  has been previously communicated securely to bob (by any number of secure protocols) and stored.
	// since i think we want a fresh Paillier system each time we will start the protocol by encrypting x1 and transmitting to bob.

	cKey, _ := paillier.Encrypt(&ahsPrivKeyAlice.PublicKey, x1.Bytes())

	// compat with ethereum.
	// TODO: doesn't seem to require that message hash is within the curve order when treated as a number, even though the bit length is required to be the same
	msgHashBytes := crypto.Keccak256([]byte("this is the message"))
	mPrime := new(big.Int).SetBytes(msgHashBytes)

	/*
	where 'sid' is session ID ...
	1. P1’s first message:
		(a) P1 chooses a random keyShare ← Zq and computes R1 = keyShare · G.
		(b) P1 sends (com-prove, sid|1, R1, keyShare) to FRDLcom-zk. TODO: no ZK for now ...
	 */
	k1 := tecdsa.MakeRandoIntWithOrder(Zq)
	xR1, yR1 := theCurve.ScalarBaseMult(k1.Bytes())
	R1 := ecdsa.PublicKey{ Curve:theCurve, X: xR1, Y: yR1}

	/*
	2. P2’s first message:
		(a) P2 receives (proof-receipt, sid|1) from FRDLcom-zk.
		(b) P2 chooses a random k2 ← Zq and computes R2 = k2 · G.
		(c) P2 sends (prove, sidk2, R2, k2) to FRDLzk .
	 */

	k2 := tecdsa.MakeRandoIntWithOrder(Zq)
	xR2, yR2 := theCurve.ScalarBaseMult(k2.Bytes())
	R2 := ecdsa.PublicKey{ Curve: theCurve, X: xR2, Y: yR2}

	/*
	3. P1’s second message:
		(a) P1 receives (proof, sidk2, R2) from FRDLzk ; if not, it aborts.
		(b) P1 sends (decom-proof, sidk1) to Fcom-zk.
	 */
	// basically - other than ZK's - P1 just receives R2 from P2

	/*
	4. P2’s second message:
		(a) P2 receives (decom-proof, sidk1, R1) from FRDLcom-zk; if not, it aborts.
		(b) P2 computes R = k2 · R1. Denote R = (rx, ry). Then, P2 computes r = rx mod q.
		(c) P2 chooses a random ρ ← Zq2 and computes c1 = Encpk(ρ · q + (k2)−1 · m0 mod q.
		Then, P2 computes v = (k2)−1 · r · x2 mod q, c2 = v  ckey and c3 = c1 ⊕ c2.
		(d) P2 sends c3 to P1.
	 */
	// P2 receives R1 from P1
	// R = k2 * R1
	Rx2, _ := theCurve.ScalarMult(R1.X, R1.Y, k2.Bytes())
	r2 := new(big.Int).Mod(Rx2, Zq)

	Zq2 := new(big.Int).Exp(Zq, big.NewInt(2), nil)
	rho := tecdsa.MakeRandoIntWithOrder(Zq2)

	// compute c1 ...
	qRho := new(big.Int).Mul(rho, Zq) // assume not mod since easily within order of Paillier
	xx := new(big.Int).ModInverse(k2, Zq)
	xx.Mul(xx, mPrime)
	xx.Mod(xx, Zq)
	xx.Add(xx, qRho)

	c1, _ := paillier.Encrypt(&ahsPrivKeyAlice.PublicKey, xx.Bytes())

	// compute v ...
	v := new(big.Int).ModInverse(k2, Zq)
	v.Mul(v, r2)
	v.Mul(v, x2)
	v.Mod(v, Zq)

	c2 := paillier.Mul(&ahsPrivKeyAlice.PublicKey, cKey, v.Bytes())

	c3 := paillier.AddCipher(&ahsPrivKeyAlice.PublicKey, c1, c2)

	// P2 sends c3 to P1 ...

	// P1 has already received R2
	Rx1, _ := theCurve.ScalarMult(R2.X, R2.Y, k1.Bytes())
	r1 := new(big.Int).Mod(Rx1, Zq)

	if r1.Cmp(r2) != 0 {
		t.Errorf("P1 and P2 should computed the same value for r: %v, %v", r1, r1)
	}

	spBytes, _ := paillier.Decrypt(ahsPrivKeyAlice, c3)
	sp := new(big.Int).SetBytes(spBytes)
	sp.Mod(sp, Zq)
	spp := new(big.Int).ModInverse(k1, Zq)
	spp.Mul(spp, sp)
	spp.Mod(spp, Zq)

	s := spp
	maybeSmaller := new(big.Int).Sub(Zq, spp)
	if maybeSmaller.Cmp(s) < 0 {
		s = maybeSmaller
	}

	// (r, s) is the signature

	// ETH version ...
	ethVerify := crypto.VerifySignature(
		theCurve.Marshal(privAlice.X, privAlice.Y),
		msgHashBytes,
		append(r1.Bytes(), s.Bytes()...))
	if !ethVerify {
		t.Errorf("multi-party signature did not verify with eth")
	}

	// Golang version ...
	pkECDSA := ecdsa.PublicKey{theCurve, privAlice.X, privAlice.Y}
	if !ecdsa.Verify(&pkECDSA, msgHashBytes, r1, s) {
		t.Errorf("multi-party signature did not verify correctly: %v, %v", r1, s)
	}
}

func TestBasicSchnorr(t *testing.T) {

	 // Alice wants to prove to Bob that she knows x: the discrete logarithm of y = g^x to the base g.
	theCurve := secp256k1.S256()
	Zq := theCurve.N

	// in this case we will essentially be proving that alice knows the private key of this key pair
	privAlice, _ := ecies.GenerateKey(rand.Reader, theCurve, nil)

	// Alice picks a random v in Zq, computes t = g^v and sends t to Bob.
	v := tecdsa.MakeRandoIntWithOrder(Zq)
	tx, ty := theCurve.ScalarBaseMult(v.Bytes())

	// Bob picks a random c in Zq (the challenge) and sends it to Alice.
	c := tecdsa.MakeRandoIntWithOrder(Zq)

	// Alice computes r = v - cx mod Zq and returns r to Bob.
	r := new(big.Int).Mul(c, privAlice.D)
	r.Sub(v, r)
	r.Mod(r, Zq)

	// Bob checks whether t = g^r * y^c.
	x1, y1 := theCurve.ScalarBaseMult(r.Bytes())
	x2, y2 := theCurve.ScalarMult(privAlice.X, privAlice.Y, c.Bytes())
	zx, zy := theCurve.Add(x1, y1, x2, y2)

	if tx.Cmp(zx) != 0 || ty.Cmp(zy) != 0 {
		t.Error("discrete log signature check failed")
	}
}

func TestNIZKSchnorr(t *testing.T) {

	theCurve := secp256k1.S256()
	Zq := theCurve.N

	// these steps are the same as the interactive protocol ...
	privAlice, _ := ecies.GenerateKey(rand.Reader, theCurve, nil)

	v := tecdsa.MakeRandoIntWithOrder(Zq)
	tx, ty := theCurve.ScalarBaseMult(v.Bytes())

	hasher := sha256.New()

	// Alice computes c = H(g, y, t)
	hasher.Write(theCurve.Gx.Bytes())
	hasher.Write(privAlice.X.Bytes())
	hasher.Write(tx.Bytes())
	c := new(big.Int).SetBytes(hasher.Sum(nil))
	// c.Mod(c, Zq)

	// Alice computes r = v - cx mod Zq and returns r to Bob.
	r := new(big.Int).Mul(c, privAlice.D)
	r.Sub(v, r)
	r.Mod(r, Zq)

	// Bob checks whether t = g^r * y^c.
	// TODO: i haven't seen it stated explicitly but I assume alice transmits 't' to bob and he uses it and the publicly
	//  available g and y to calculate c for himself ...
	x1, y1 := theCurve.ScalarBaseMult(r.Bytes())
	x2, y2 := theCurve.ScalarMult(privAlice.X, privAlice.Y, c.Bytes())
	zx, zy := theCurve.Add(x1, y1, x2, y2)

	if tx.Cmp(zx) != 0 || ty.Cmp(zy) != 0 {
		t.Error("discrete log signature check failed")
	}
}