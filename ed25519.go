package signalprotocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

const ED25519_PEM_TYPE = "ED25519 PRIVATE KEY"

type Ed25519KeyPair struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// Generates new Ed25519 key pair
func GenerateEd25519KeyPair() (*Ed25519KeyPair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &Ed25519KeyPair{Private: privateKey, Public: publicKey}, nil
}

// Load PKCS#8-encoded Ed25519 private key from an io.Reader
func LoadEd25519KeyPair(in io.Reader) (*Ed25519KeyPair, error) {
	// Read all bytes from the input stream
	data, err := io.ReadAll(in)
	if err != nil {
		return nil, err
	}

	// Decode the PEM block
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, err
	}

	// Validates PEM block
	if block.Type != ED25519_PEM_TYPE {
		return nil, fmt.Errorf("invalid PEM block")
	}

	// Parse the PKCS#8-encoded private key
	privateKeyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Ensure the parsed key is an Ed25519 private key
	privateKey, ok := privateKeyAny.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("parsed key is not an Ed25519 private key")
	}

	// Derive the corresponding public key from the private key
	publicKey := privateKey.Public().(ed25519.PublicKey)

	return &Ed25519KeyPair{Private: privateKey, Public: publicKey}, nil
}

// Writes the private key to an io.Writer as PKCS#8-encoded PEM block
func (e *Ed25519KeyPair) SaveKeyPair(out io.Writer) error {
	// Marshal private key to PKCS#8 format
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(e.Private)
	if err != nil {
		return err
	}

	// Create a PEM block with the private key
	pemBlock := &pem.Block{
		Type:  ED25519_PEM_TYPE,
		Bytes: privateKeyBytes,
	}

	err = pem.Encode(out, pemBlock)
	return err
}

// Sign the message
func (e *Ed25519KeyPair) Sign(message []byte) []byte {
	return ed25519.Sign(e.Private, message)
}

// Verify the signature
func VerifySignature(publicKey ed25519.PublicKey, message []byte, signature []byte) bool {
	return ed25519.Verify(publicKey, message, signature)
}
