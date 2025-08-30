package signalprotocol

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

// Verifies that the Ed25519 key pair can be saved and loaded correctly
func TestSaveAndLoadEd25519KeyPair(t *testing.T) {
	// Generate key pair
	keyPair, err := GenerateEd25519KeyPair()
	require.NoError(t, err, "failed to generate ed25519 key pair")

	// Save the key pair to a buffer
	var buf bytes.Buffer
	err = keyPair.SaveKeyPair(&buf)
	require.NoError(t, err, "failed to save key pair")

	// Load the key pair from the buffer
	loadedKeyPair, err := LoadEd25519KeyPair(&buf)
	require.NoError(t, err, "failed to load key pair")

	// Verify private keys
	require.Equal(t, keyPair.Private, loadedKeyPair.Private, "loaded private key does not match the original key")
}

// Verifies the signing and verification of messages with Ed25519 key pair
func TestSignature(t *testing.T) {
	// Generate key pair.
	keyPair, err := GenerateEd25519KeyPair()
	require.NoError(t, err, "failed to generate ed25519 key pair")

	// Test case 1: Valid signature verification
	message := []byte("test message")
	signature := keyPair.Sign(message)
	require.True(t, VerifySignature(keyPair.Public, message, signature), "signature verification failed for valid signature")

	// Test case 2: Invalid signature (tampered message)
	tamperedMessage := []byte("tampered message")
	require.False(t, VerifySignature(keyPair.Public, tamperedMessage, signature), "signature verification should fail for tampered message")

	// Test case 3: Invalid signature (wrong public key)
	wrongKeyPair, err := GenerateEd25519KeyPair()
	require.NoError(t, err, "failed to generate wrong ed25519 key pair")
	require.False(t, VerifySignature(wrongKeyPair.Public, message, signature), "signature verification should fail with wrong public key")

	// Test case 4: Invalid signature (corrupted signature)
	corruptedSignature := make([]byte, len(signature))
	_, err = rand.Read(corruptedSignature)
	require.NoError(t, err, "failed to generate random corrupted signature")
	require.False(t, VerifySignature(keyPair.Public, message, corruptedSignature), "signature verification should fail for corrupted signature")

	// Test case 5: Empty message and signature
	emptyMessage := []byte{}
	emptySignature := keyPair.Sign(emptyMessage)
	require.True(t, VerifySignature(keyPair.Public, emptyMessage, emptySignature), "signature verification failed for empty message")
}
