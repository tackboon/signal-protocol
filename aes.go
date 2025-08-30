package signalprotocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

type AesGcm struct {
	Key []byte
}

// Generates new AES-256 GCM instance with 32 byte key
func NewAesGcm(key []byte) AesGcm {
	return AesGcm{Key: key}
}

// Create AES-256 GCM cipher
func (a AesGcm) createGCM() (cipher.AEAD, error) {
	// Create AES cipher block
	block, err := aes.NewCipher(a.Key)
	if err != nil {
		return nil, err
	}

	// Return new GCM cipher
	return cipher.NewGCM(block)
}

// Encrypts the plain text using AES-256 GCM
func (a AesGcm) Encrypt(plainText []byte) ([]byte, error) {
	// Create new GCM cipher
	gcm, err := a.createGCM()
	if err != nil {
		return nil, err
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	// Computes cipher data
	cipherText := gcm.Seal(nonce, nonce, plainText, nil)
	return cipherText, nil
}

// Decrypts AES-256 GCM cipher data
func (a AesGcm) Decrypt(cipherText []byte) ([]byte, error) {
	// Create new GCM cipher
	gcm, err := a.createGCM()
	if err != nil {
		return nil, err
	}

	// Validate cipher data
	nonceSize := gcm.NonceSize()
	if len(cipherText) < nonceSize {
		return nil, fmt.Errorf("cipher data is too short")
	}

	// Extracts nonce and encrypted message
	nonce, encryptedMessage := cipherText[:nonceSize], cipherText[nonceSize:]

	// Decrypts data
	plainText, err := gcm.Open(nil, nonce, encryptedMessage, nil)
	return plainText, err
}
