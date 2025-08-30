package signalprotocol

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

// Tests teh X3DH key exchange for both initiator and responder
func TestX3dhKeyExchange(t *testing.T) {
	var err error

	// Create initiator
	initiator := X3dhInitiator{}

	initiator.IdentityKey, err = GenerateEcdhKeyPair()
	require.NoError(t, err, "failed to generate initiator's identity key")

	initiator.EphemeralKey, err = GenerateEcdhKeyPair()
	require.NoError(t, err, "failed to generate initiator's ephemeral key")

	// Create initiator's public key bundle
	initiatorBundle := X3dhInitiatorBundleKey{
		IdentityKey:  initiator.IdentityKey.Public,
		EphemeralKey: initiator.EphemeralKey.Public,
	}

	// Create responder
	responder := X3dhResponder{}

	responder.IdentityKey, err = GenerateEcdhKeyPair()
	require.NoError(t, err, "failed to generate responder's identity key")

	responder.SignedPreKey, err = GenerateEcdhKeyPair()
	require.NoError(t, err, "failed to generate responder's signed prekey")

	responder.OneTimePreKey, err = GenerateEcdhKeyPair()
	require.NoError(t, err, "failed to generate responder's one-time prekey")

	// Generate Ed25519 key pair for responder
	signKey, err := GenerateEd25519KeyPair()
	require.NoError(t, err, "failed to generate sign key")

	// Sign responder's signed prekey
	signedPreKeySig := signKey.Sign(responder.SignedPreKey.Public.Bytes())

	// Create responder's public key bundle
	responderBundle := X3dhResponderBundleKey{
		IdentityKey:     responder.IdentityKey.Public,
		SignedPreKey:    responder.SignedPreKey.Public,
		SignedPreKeySig: signedPreKeySig,
		IdentitySignKey: signKey.Public,
		OneTimePreKey:   responder.OneTimePreKey.Public,
	}

	// Test case 1: Valid key exchange
	salt := []byte("X3DH Salt")
	info := []byte("X3DH Key Derivation")

	shared1, err := DeriveInitiatorKey(&initiator, &responderBundle, salt, info)
	require.NoError(t, err, "failed to derive initiator key with valid inputs")

	shared2, err := DeriveResponderKey(&responder, &initiatorBundle, salt, info)
	require.NoError(t, err, "failed to derive responder key with valid inputs")

	require.Equal(t, shared1, shared2, "shared secrets do not match")

	// Test case 2: Invalid signature
	corruptedSig := make([]byte, len(signedPreKeySig))
	_, err = rand.Read(corruptedSig)
	require.NoError(t, err, "failed to generate random corrupted signature")

	responderBundle.SignedPreKeySig = corruptedSig
	_, err = DeriveInitiatorKey(&initiator, &responderBundle, salt, info)
	require.Error(t, err, "expected error for invalid signature")
}
