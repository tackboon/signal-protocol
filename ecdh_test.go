package signalprotocol

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// Verifies that the ecdh key pair can be saved and loaded correctly
func TestSaveAndLoadEcdhKeyPair(t *testing.T) {
	// Generate key pair
	keyPair, err := GenerateEcdhKeyPair()
	require.NoError(t, err, "failed to generate ecdh key pair")

	// Save the key pair to a buffer
	var buf bytes.Buffer
	err = keyPair.SaveKeyPair(&buf)
	require.NoError(t, err, "failed to save key pair")

	// Load the key pair from the buffer
	loadedKeyPair, err := LoadEcdhKeyPair(&buf)
	require.NoError(t, err, "failed to load key pair")

	// Verify private keys
	require.Equal(t, keyPair.Private.Bytes(), loadedKeyPair.Private.Bytes(), "loaded private key does not match the original key")
}

// Verifies the ECDH produces the same shared secret for both parties
func TestECDH(t *testing.T) {
	// Generate two key pairs
	keyPair1, err := GenerateEcdhKeyPair()
	require.NoError(t, err, "failed to generate key pair 1")

	keyPair2, err := GenerateEcdhKeyPair()
	require.NoError(t, err, "failed to generate key pair 2")

	// Perform ECDH in both directions
	salt := []byte("test-salt")
	info := []byte("test-info")
	shared1, err := keyPair1.ECDH(keyPair2.Public, salt, info)
	require.NoError(t, err, "failed to perform ECDH for private key 1 and public key 2")

	shared2, err := keyPair2.ECDH(keyPair1.Public, salt, info)
	require.NoError(t, err, "failed to perform ECDH for private key 2 and public key 1")

	// Verify the shared secrets match
	require.Equal(t, shared1, shared2, "shared secrets do not match")

	// Test invalid peer public key
	keyPair3, err := GenerateEcdhKeyPair()
	require.NoError(t, err, "failed to generate key pair 3")

	shared3, err := keyPair1.ECDH(keyPair3.Public, salt, info)
	require.NoError(t, err, "failed to perform ECDH for private key 1 and public key 3")
	require.NotEqual(t, shared1, shared3)
}
