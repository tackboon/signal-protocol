package signalprotocol

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

const ECDH_PEM_TYPE = "X25519 PRIVATE KEY"

type EcdhKeyPair struct {
	Private *ecdh.PrivateKey
	Public  *ecdh.PublicKey
}

// Generates new X25519 key pair
func GenerateEcdhKeyPair() (*EcdhKeyPair, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	publicKey := privateKey.PublicKey()

	return &EcdhKeyPair{Private: privateKey, Public: publicKey}, nil
}

// Load PKCS#8-encoded X25519 private key from an io.Reader
func LoadEcdhKeyPair(in io.Reader) (*EcdhKeyPair, error) {
	// Read all bytes from the input stream
	data, err := io.ReadAll(in)
	if err != nil {
		return nil, err
	}

	// Decode the PEM block
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Validates PEM block
	if block.Type != ECDH_PEM_TYPE {
		return nil, fmt.Errorf("invalid PEM block")
	}

	// Parse the PKCS#8-encoded private key
	privateKeyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Ensure the parsed key is an X25519 private key
	privateKey, ok := privateKeyAny.(*ecdh.PrivateKey)
	if !ok || privateKey.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("parsed key is not an x25519 private key")
	}

	// Derive the corresponding public key from the private key
	publicKey := privateKey.PublicKey()

	return &EcdhKeyPair{Private: privateKey, Public: publicKey}, nil
}

// Writes the private key to an io.Writer as PKCS#8-encoded PEM block
func (kp *EcdhKeyPair) SaveKeyPair(out io.Writer) error {
	// Marshal private key to PKCS#8 format
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(kp.Private)
	if err != nil {
		return err
	}

	// Create a PEM block with the private key
	pemBlock := &pem.Block{
		Type:  ECDH_PEM_TYPE,
		Bytes: privateKeyBytes,
	}

	// Encode and write the PEM block to the output stream
	err = pem.Encode(out, pemBlock)
	return err
}

// Performs elliptic Diffie-Hellman key exchange
func (kp *EcdhKeyPair) RawECDH(peerPublicKey *ecdh.PublicKey) ([]byte, error) {
	// Compute raw Diffie-Hellman shared secret
	share, err := kp.Private.ECDH(peerPublicKey)
	return share, err
}

// Performs elliptic Diffie-Hellman key exchange with HKDF to derive a shared key
func (kp *EcdhKeyPair) ECDH(peerPublicKey *ecdh.PublicKey, salt []byte, info []byte) ([]byte, error) {
	// Compute raw Diffie-Hellman shared secret
	share, err := kp.Private.ECDH(peerPublicKey)
	if err != nil {
		return nil, err
	}

	// Generate pseudorandom key
	prk := HkdfExtract(salt, share)

	// Derive a key of 32 bytes
	key := HkdfExpand(prk, info, 32)

	return key, nil
}

// Implements the HKDF-Extract phase per RFC 5869
func HkdfExtract(salt []byte, ikm []byte) []byte {
	// If no salt is provided, use a zeroed salt of length equal to SHA-256 output (32 bytes)
	if len(salt) == 0 {
		salt = make([]byte, sha256.New().Size())
	}

	// Compute HMAC-SHA256 to produce psedorandom key
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)

	return h.Sum(nil)
}

// Implements the HKDF-Expand phase per RFC 5869
func HkdfExpand(prk []byte, info []byte, keyLength int) []byte {
	var t []byte                      // Holds the previous HMAC output (empty for first iteration)
	var i byte = 1                    // Counter for HMAC iterations, starting at 1
	out := make([]byte, 0, keyLength) // Pre-allocate output slice for efficiency

	// Continue generating HMAC outputs until the desired key length is reached
	for len(out) < keyLength {
		// Create a new HMAC-SHA256 instance with the PRK as the key
		h := hmac.New(sha256.New, prk)

		// Input the previous HMAC output (or empty for first iteration)
		h.Write(t)

		// Input the context-specific info string (optional, provides domain separation)
		h.Write(info)

		// Input the counter as a single byte to differentiate iterations
		h.Write([]byte{i})

		// Compute the HMAC-SHA256 digest for this iteration
		t = h.Sum(nil)

		// Append the digest to the output
		out = append(out, t...)

		// Increment the counter for the next iteration
		i++
	}

	return out[:keyLength]
}
