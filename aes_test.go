package signalprotocol

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

// Verifies that encryption and decryption work correctly
func TestEncryptAndDecrypt(t *testing.T) {
	// Prepare test case
	plainText := []byte("this is a test message!")

	// Generate key for AES-256
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err, "failed to generate key")

	// Encrypt data
	aesGcm := NewAesGcm(key)
	cipherText, err := aesGcm.Encrypt(plainText)
	require.NoError(t, err)

	// Decrypt and verify the result
	decryptedText, err := aesGcm.Decrypt(cipherText)
	require.NoError(t, err, "failed to decrypt cipher data")
	require.Equal(t, plainText, decryptedText, "decrypted result not match")
}
