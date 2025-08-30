package signalprotocol

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// Tests the Double Ratchet protocol implementation.
func TestDoubleRatchet(t *testing.T) {
	// Simulated X3DH shared secret (32 bytes for AES-256).
	sharedSecret := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, sharedSecret)
	require.NoError(t, err, "failed to simulate X3DH shared secret")

	salt := []byte("salt")
	info := []byte("info")

	// Test 1: Basic encryption and decryption
	t.Run("BasicEncryptDecrypt", func(t *testing.T) {
		// Initialize users' ratchet states
		aliceState, err := InitializeRatchet(sharedSecret)
		require.NoError(t, err, "failed to initialized Alice's ratcher state")
		bobState, err := InitializeRatchet(sharedSecret)
		require.NoError(t, err, "failed to initialized Bob's ratcher state")

		// Encrypts message
		message := "Hello, Bob!"
		encryptedMsg, err := aliceState.EncryptMessage(message, salt, info)
		require.NoError(t, err, "failed to encrypt message")

		// Decrypts message
		decryptedMsg, err := bobState.DecryptMessage(*encryptedMsg, salt, info)
		require.NoError(t, err, "failed to decrypt message")
		require.Equal(t, message, decryptedMsg, "decrypted message unmatch")
	})

	// Test 2: Multiple messages in order
	t.Run("MultipleMessagesInOrder", func(t *testing.T) {
		// Initialize users' ratchet states
		aliceState, err := InitializeRatchet(sharedSecret)
		require.NoError(t, err, "failed to initialized Alice's ratcher state")
		bobState, err := InitializeRatchet(sharedSecret)
		require.NoError(t, err, "failed to initialized Bob's ratcher state")

		messages := []string{"Msg1", "Msg2", "Msg3"}
		var encryptedMsgs []*Message

		// Alice encrypts multiple messages
		for _, msg := range messages {
			encryptedMsg, err := aliceState.EncryptMessage(msg, salt, info)
			require.NoError(t, err, "failed to encrypt message")
			encryptedMsgs = append(encryptedMsgs, encryptedMsg)
		}

		// Bob decrypts messages in order
		for i, encryptedMsg := range encryptedMsgs {
			decryptedMsg, err := bobState.DecryptMessage(*encryptedMsg, salt, info)
			require.NoError(t, err, "failed to decrypt message")
			require.Equal(t, messages[i], decryptedMsg, "decrypted message unmatch")
		}
	})

	// Test 3: Skipped messages (out-of-order delivery)
	t.Run("SkippedMessages", func(t *testing.T) {
		// Initialize users' ratchet states
		aliceState, err := InitializeRatchet(sharedSecret)
		require.NoError(t, err, "failed to initialized Alice's ratcher state")
		bobState, err := InitializeRatchet(sharedSecret)
		require.NoError(t, err, "failed to initialized Bob's ratcher state")

		messages := []string{"Msg1", "Msg2", "Msg3"}
		var encryptedMsgs []*Message

		// Alice sends three messages
		for _, msg := range messages {
			encryptedMsg, err := aliceState.EncryptMessage(msg, salt, info)
			require.NoError(t, err, "failed to encrypt message")
			encryptedMsgs = append(encryptedMsgs, encryptedMsg)
		}

		// Bob receives msg3 first (skipping msg1 and msg2)
		msgOrders := []int{2, 0, 1}
		for _, i := range msgOrders {
			decryptedMsg, err := bobState.DecryptMessage(*encryptedMsgs[i], salt, info)
			require.NoError(t, err, "failed to decrypt message")
			require.Equal(t, messages[i], decryptedMsg, "decrypted message unmatch")
		}

		// Verify that skipped message keys are cleared
		require.Equal(t, len(bobState.skippedMsgKeyMap), 0, "skipped message keys not being cleared")
	})

	// Test 4: DH ratchet step
	t.Run("DHRatchet", func(t *testing.T) {
		// Initialize users' ratchet states
		aliceState, err := InitializeRatchet(sharedSecret)
		require.NoError(t, err, "failed to initialized Alice's ratcher state")
		bobState, err := InitializeRatchet(sharedSecret)
		require.NoError(t, err, "failed to initialized Bob's ratcher state")

		// Alice sends a message
		msg1 := "Alice's message 1"
		encryptedMsg1, err := aliceState.EncryptMessage(msg1, salt, info)
		require.NoError(t, err, "failed to encrypt message")

		// Bob receives and decrypts it
		decryptedMsg1, err := bobState.DecryptMessage(*encryptedMsg1, salt, info)
		require.NoError(t, err, "failed to decrypt message")
		require.Equal(t, msg1, decryptedMsg1, "decrypted message unmatch")

		// Bob sends a message
		msg2 := "Bob's message 1"
		encryptedMsg2, err := bobState.EncryptMessage(msg2, salt, info)
		require.NoError(t, err, "failed to encrypt message")

		// Alice receives and decrypts it
		decryptedMsg2, err := aliceState.DecryptMessage(*encryptedMsg2, salt, info)
		require.NoError(t, err, "failed to decrypt message")
		require.Equal(t, msg2, decryptedMsg2, "decrypted message unmatch")

		// Alice sends a message
		msg3 := "Alice's message 2"
		encryptedMsg3, err := aliceState.EncryptMessage(msg3, salt, info)
		require.NoError(t, err, "failed to encrypt message")

		// Bob receives and decrypts it
		decryptedMsg3, err := bobState.DecryptMessage(*encryptedMsg3, salt, info)
		require.NoError(t, err, "failed to decrypt message")
		require.Equal(t, msg3, decryptedMsg3, "decrypted message unmatch")

		// Verify that PrevSendChainLen is set correctly.
		require.Equal(t, uint32(0), encryptedMsg3.Header.PrevChainLen, "incorrect PrevChainLen")
	})

	// Test 5: Out-of-order message after DH ratchet.
	t.Run("OutOfOrderAfterDHRatchet", func(t *testing.T) {
		// Initialize users' ratchet states
		aliceState, err := InitializeRatchet(sharedSecret)
		require.NoError(t, err, "failed to initialized Alice's ratcher state")
		bobState, err := InitializeRatchet(sharedSecret)
		require.NoError(t, err, "failed to initialized Bob's ratcher state")

		// Alice sends two messages in the first chain
		msg1 := "Alice's message 1"
		encryptedMsg1, err := aliceState.EncryptMessage(msg1, salt, info)
		require.NoError(t, err, "failed to encrypt message 1")
		msg2 := "Alice's message 2"
		encryptedMsg2, err := aliceState.EncryptMessage(msg2, salt, info)
		require.NoError(t, err, "failed to encrypt message 2")

		// Bob sends a message to trigger a DH ratchet in Alice
		bobMsg := "Bob's message 1"
		encryptedBobMsg, err := bobState.EncryptMessage(bobMsg, salt, info)
		require.NoError(t, err, "failed to encrypt Bob's message")

		// Alice receives Bob's message, triggering a DH ratchet
		decryptedBobMsg, err := aliceState.DecryptMessage(*encryptedBobMsg, salt, info)
		require.NoError(t, err, "failed to decrypt Bob's message")
		require.Equal(t, bobMsg, decryptedBobMsg, "decrypted message unmatch")

		// Alice sends a third message in the new chain
		msg3 := "Alice's message 3"
		encryptedMsg3, err := aliceState.EncryptMessage(msg3, salt, info)
		require.NoError(t, err, "failed to encrypt message 3")

		// Bob receives msg3 first (triggers DH ratchet)
		decryptedMsg3, err := bobState.DecryptMessage(*encryptedMsg3, salt, info)
		require.NoError(t, err, "failed to decrypt message 3")
		require.Equal(t, msg3, decryptedMsg3, "decrypted message 3 does not match")

		// Bob receives msg1 (from previous chain, should use stored key)
		decryptedMsg1, err := bobState.DecryptMessage(*encryptedMsg1, salt, info)
		require.NoError(t, err, "failed to decrypt message 1")
		require.Equal(t, msg1, decryptedMsg1, "decrypted message 1 does not match")

		// Bob receives msg2 (from previous chain, should use stored key)
		decryptedMsg2, err := bobState.DecryptMessage(*encryptedMsg2, salt, info)
		require.NoError(t, err, "failed to decrypt message 2")
		require.Equal(t, msg2, decryptedMsg2, "decrypted message 2 does not match")

		// Verify that skipped message keys are cleared
		peerKeyBytes := encryptedMsg1.Header.DHPublicKey.Bytes()
		peerKeyStr := base64.StdEncoding.EncodeToString(peerKeyBytes)
		require.Equal(t, 0, len(bobState.skippedMsgKeyMap[peerKeyStr]), "skipped message keys not cleared")
	})

	// Test 6: Error handling for invalid ciphertext
	t.Run("InvalidCiphertext", func(t *testing.T) {
		// Initialize users' ratchet states
		aliceState, err := InitializeRatchet(sharedSecret)
		require.NoError(t, err, "failed to initialized Alice's ratcher state")
		bobState, err := InitializeRatchet(sharedSecret)
		require.NoError(t, err, "failed to initialized Bob's ratcher state")

		// Alice encrypts a message
		encryptedMsg, err := aliceState.EncryptMessage("Test", salt, info)
		require.NoError(t, err, "failed to encrypt message")

		// Corrupt the ciphertext
		encryptedMsg.CipherText = "invalid-base64"

		// Bob tries to decrypt (should fail)
		_, err = bobState.DecryptMessage(*encryptedMsg, salt, info)
		require.Error(t, err, "failed to decrypt message")
	})
}
