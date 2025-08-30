package signalprotocol

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"fmt"
)

type X3dhInitiator struct {
	IdentityKey  *EcdhKeyPair
	EphemeralKey *EcdhKeyPair
}

type X3dhInitiatorBundleKey struct {
	IdentityKey  *ecdh.PublicKey
	EphemeralKey *ecdh.PublicKey
}

type X3dhResponder struct {
	IdentityKey   *EcdhKeyPair
	SignedPreKey  *EcdhKeyPair
	OneTimePreKey *EcdhKeyPair
}

type X3dhResponderBundleKey struct {
	IdentityKey     *ecdh.PublicKey
	SignedPreKey    *ecdh.PublicKey
	SignedPreKeySig []byte
	IdentitySignKey ed25519.PublicKey
	OneTimePreKey   *ecdh.PublicKey
}

// Perform X3DH key exchange for the initiator
func DeriveInitiatorKey(initiator *X3dhInitiator, peerBundleKey *X3dhResponderBundleKey, salt []byte, info []byte) ([]byte, error) {
	// Verify the responder's signed prekey signature.
	if peerBundleKey.SignedPreKey == nil || peerBundleKey.SignedPreKeySig == nil || len(peerBundleKey.IdentitySignKey) == 0 {
		return nil, fmt.Errorf("responder's signed prekey, signature, or identity signing key is nil")
	}
	publicKeyBytes := peerBundleKey.SignedPreKey.Bytes()
	if !VerifySignature(peerBundleKey.IdentitySignKey, publicKeyBytes, peerBundleKey.SignedPreKeySig) {
		return nil, fmt.Errorf("invalid signed prekey signature")
	}

	// DH1: Initiator identity key with responder signed pre-key
	dh1, err := initiator.IdentityKey.RawECDH(peerBundleKey.SignedPreKey)
	if err != nil {
		return nil, err
	}

	// DH2: Initiator Ephemeral key with responder identity key
	dh2, err := initiator.EphemeralKey.RawECDH(peerBundleKey.IdentityKey)
	if err != nil {
		return nil, err
	}

	// DH3: Initiator Ephemeral key with responder one-time key
	dh3, err := initiator.EphemeralKey.RawECDH(peerBundleKey.OneTimePreKey)
	if err != nil {
		return nil, err
	}

	// Concatenate DH outputs
	concat := append(dh1, append(dh2, dh3...)...)

	// Generate pseudorandom key
	prk := HkdfExtract(salt, concat)

	// Derive a key of 32 bytes
	secret := HkdfExpand(prk, info, 32)
	return secret, nil
}

// Performs X3DH key exchange for the responder
func DeriveResponderKey(responder *X3dhResponder, peerBundleKey *X3dhInitiatorBundleKey, salt []byte, info []byte) ([]byte, error) {
	// DH1: Responder signed pre-key with initiator identity key
	dh1, err := responder.SignedPreKey.RawECDH(peerBundleKey.IdentityKey)
	if err != nil {
		return nil, err
	}

	// DH2: Responder identity key with initiator ephemeral key
	dh2, err := responder.IdentityKey.RawECDH(peerBundleKey.EphemeralKey)
	if err != nil {
		return nil, err
	}

	// DH3: Responder one-time key with initiator ephemeral key
	dh3, err := responder.OneTimePreKey.RawECDH(peerBundleKey.EphemeralKey)
	if err != nil {
		return nil, err
	}

	// Concatenate DH outputs
	concat := append(dh1, append(dh2, dh3...)...)

	// Generate pseudorandom key
	prk := HkdfExtract(salt, concat)

	// Derive a key of 32 bytes
	secret := HkdfExpand(prk, info, 32)
	return secret, nil
}
