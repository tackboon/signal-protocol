# Signal Protocol Implementation in Go

This repository provides a Go implementation of the [Signal Protocol](https://signal.org/docs/), specifically the Double Ratchet algorithm, for secure end-to-end encrypted messaging. The implementation supports key derivation, message encryption/decryption, and handling of out-of-order messages using the Double Ratchet’s symmetric and asymmetric ratchet steps.

## Features
- **Double Ratchet Algorithm**: Implements the core Signal Protocol with Diffie-Hellman (DH) ratchet and symmetric ratchet for forward secrecy and post-compromise security.
- **Out-of-Order Message Handling**: Stores skipped message keys to decrypt messages received out of order.
- **AES-GCM Encryption**: Uses AES-GCM for secure message encryption and authentication.
- **HKDF Key Derivation**: Derives message and chain keys using HMAC-based Key Derivation Function (HKDF).

## Installation
```bash
go get github.com/tackboon/signal-protocol
```

## Usage
This package provides the core functionality for initializing a ratchet state, encrypting, and decrypting messages. Below is an example of a simple messaging scenario between Alice and Bob.

```go
package main

import (
	"bytes"
	"fmt"

	signalprotocol "github.com/tackboon/signal-protocol"
)

func main() {
	// Simulate X3DH key exchange
	sharedSecret, err := simulateX3DH()
	if err != nil {
		panic("failed to simulate X3DH key exchange")
	}

	// Basic encryption and decryption with double-ratchet
	// Initialize users' ratchet states
	aliceState, _ := signalprotocol.InitializeRatchet(sharedSecret)
	bobState, _ := signalprotocol.InitializeRatchet(sharedSecret)

	// Encrypts message
	message := "Hello, Bob!"
	encryptedMsg, err := aliceState.EncryptMessage(message, nil, nil)
	if err != nil {
		panic("failed to encrypt message")
	}

	// Decrypts message
	decryptedMsg, err := bobState.DecryptMessage(*encryptedMsg, nil, nil)
	if err != nil {
		panic("failed to decrypt message")
	}

	fmt.Printf("%s\n", decryptedMsg)
}

func simulateX3DH() ([]byte, error) {
	// Create initiator
	initiator := signalprotocol.X3dhInitiator{}
	initiator.IdentityKey, _ = signalprotocol.GenerateEcdhKeyPair()
	initiator.EphemeralKey, _ = signalprotocol.GenerateEcdhKeyPair()

	// Create initiator's public key bundle
	initiatorBundle := signalprotocol.X3dhInitiatorBundleKey{
		IdentityKey:  initiator.IdentityKey.Public,
		EphemeralKey: initiator.EphemeralKey.Public,
	}

	// Create responder
	responder := signalprotocol.X3dhResponder{}
	responder.IdentityKey, _ = signalprotocol.GenerateEcdhKeyPair()
	responder.SignedPreKey, _ = signalprotocol.GenerateEcdhKeyPair()
	responder.OneTimePreKey, _ = signalprotocol.GenerateEcdhKeyPair()

	// Generate Ed25519 key pair for responder
	signKey, _ := signalprotocol.GenerateEd25519KeyPair()

	// Sign responder's signed prekey
	signedPreKeySig := signKey.Sign(responder.SignedPreKey.Public.Bytes())

	// Create responder's public key bundle
	responderBundle := signalprotocol.X3dhResponderBundleKey{
		IdentityKey:     responder.IdentityKey.Public,
		SignedPreKey:    responder.SignedPreKey.Public,
		SignedPreKeySig: signedPreKeySig,
		IdentitySignKey: signKey.Public,
		OneTimePreKey:   responder.OneTimePreKey.Public,
	}

	// Exchange secret key
	shared1, err := signalprotocol.DeriveInitiatorKey(&initiator, &responderBundle, nil, nil)
	if err != nil {
		return nil, err
	}

	shared2, err := signalprotocol.DeriveResponderKey(&responder, &initiatorBundle, nil, nil)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(shared1, shared2) {
		return nil, fmt.Errorf("shared secret unmatch")
	}

	return shared1, nil
}
```