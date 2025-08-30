package signalprotocol

import (
	"crypto/ecdh"
	"encoding/base64"
)

type MessageHeader struct {
	DHPublicKey  *ecdh.PublicKey
	MsgNum       uint32
	PrevChainLen uint32
}

type Message struct {
	Header     MessageHeader
	CipherText string
}

type RatchetState struct {
	RootKey          []byte                       // Root key for deriving chain keys
	SendChainKey     []byte                       // Chain key for sending messages
	RecvChainKey     []byte                       // Chain key for receiving messages
	SendMsgNum       uint32                       // Message number for sending chain
	RecvMsgNum       uint32                       // Message number for receiving chain
	DHRatchetKey     *EcdhKeyPair                 // Current DH ratchet key pair
	PrevSendChainLen uint32                       // Length of the previous sending chain
	PeerRatchetKey   *ecdh.PublicKey              // Peer's current DH ratchet public key
	skippedMsgKeyMap map[string]map[uint32][]byte // Map of peer DH public key to message number to message key
}

// Initializes the Double Ratchet state with the X3DH shared secret.
func InitializeRatchet(sharedSecret []byte) (*RatchetState, error) {
	// Generate initial DH ratchet key pair.
	dhRatchetKey, err := GenerateEcdhKeyPair()
	if err != nil {
		return nil, err
	}

	// Initialize state with shared secret as root key and empty chain keys.
	return &RatchetState{
		RootKey:          sharedSecret,
		DHRatchetKey:     dhRatchetKey,
		SendChainKey:     nil,
		RecvChainKey:     nil,
		SendMsgNum:       0,
		RecvMsgNum:       0,
		PrevSendChainLen: 0,
		PeerRatchetKey:   nil,
		skippedMsgKeyMap: make(map[string]map[uint32][]byte),
	}, nil
}

// Derives a new message key for the symmetric ratchet
func ratchetStep(chainKey []byte, salt []byte, info []byte) (msgKey []byte, nextChainKey []byte) {
	// Use HKDF to derive message key and next chain key.
	prk := HkdfExtract(salt, chainKey)
	output := HkdfExpand(prk, info, 64)

	// 32 bytes for message key, 32 for next chain key.
	msgKey = output[:32]
	nextChainKey = output[32:64]

	return msgKey, nextChainKey
}

// Performs a Diffie-Hellman ratchet step when receiving a new DH public key.
func (rs *RatchetState) DHRatchet(peerPublicKey *ecdh.PublicKey, salt []byte, info []byte) error {
	// Perform DH with current DH ratchet key and peer's new public key.
	dhOutput, err := rs.DHRatchetKey.ECDH(peerPublicKey, salt, info)
	if err != nil {
		return err
	}

	// Update root key using HKDF with previous root key as salt.
	prk := HkdfExtract(rs.RootKey, dhOutput)
	newRootKey := HkdfExpand(prk, info, 32)
	rs.RootKey = newRootKey

	// Update peer's DH public key.
	rs.PeerRatchetKey = peerPublicKey

	// Reset receiving chain.
	_, rs.RecvChainKey = ratchetStep(rs.RootKey, salt, info)
	rs.RecvMsgNum = 0

	// Generate new DH ratchet key pair for sending.
	newDHRatchetKey, err := GenerateEcdhKeyPair()
	if err != nil {
		return err
	}
	rs.DHRatchetKey = newDHRatchetKey

	// Reset sending chain.
	_, rs.SendChainKey = ratchetStep(rs.RootKey, salt, info)
	rs.PrevSendChainLen = rs.SendMsgNum
	rs.SendMsgNum = 0

	return nil
}

// Encrypts a message using the Double Ratchet.
func (rs *RatchetState) EncryptMessage(message string, salt []byte, info []byte) (*Message, error) {
	// Advance the sending chain to get a new message key
	messageKey, nextChainKey := ratchetStep(rs.SendChainKey, salt, info)
	rs.SendChainKey = nextChainKey
	rs.SendMsgNum++

	// Encrypt the message with AES-GCM
	aesGcm := NewAesGcm(messageKey)
	ciphertext, err := aesGcm.Encrypt([]byte(message))
	if err != nil {
		return nil, err
	}
	encodedCiphertext := base64.StdEncoding.EncodeToString(ciphertext)

	// Create message with header
	msgHeader := MessageHeader{
		DHPublicKey:  rs.DHRatchetKey.Public,
		MsgNum:       rs.SendMsgNum,
		PrevChainLen: rs.PrevSendChainLen,
	}
	msg := Message{
		Header:     msgHeader,
		CipherText: encodedCiphertext,
	}

	return &msg, nil
}

// Decrypts a message using the Double Ratchet
func (rs *RatchetState) DecryptMessage(msg Message, salt []byte, info []byte) (string, error) {
	// Get the peer's DH public key as a string for the skipped message keys map
	peerKeyBytes := msg.Header.DHPublicKey.Bytes()
	peerKeyStr := base64.StdEncoding.EncodeToString(peerKeyBytes)

	// Check if the message key is already stored for this message
	if msgKeyMap, ok := rs.skippedMsgKeyMap[peerKeyStr]; ok {
		if msgKey, ok := msgKeyMap[msg.Header.MsgNum]; ok {
			// Use the stored message key for decryption
			data, err := base64.StdEncoding.DecodeString(msg.CipherText)
			if err != nil {
				return "", err
			}
			aesGcm := NewAesGcm(msgKey)
			plaintext, err := aesGcm.Decrypt(data)
			if err != nil {
				return "", err
			}

			// Remove the used message key to prevent reuse
			delete(msgKeyMap, msg.Header.MsgNum)
			if len(msgKeyMap) == 0 {
				delete(rs.skippedMsgKeyMap, peerKeyStr)
			}

			return string(plaintext), nil
		}
	}

	// Check if a DH ratchet step is needed (new peer DH public key)
	if rs.PeerRatchetKey != nil && !rs.PeerRatchetKey.Equal(msg.Header.DHPublicKey) {
		if err := rs.DHRatchet(msg.Header.DHPublicKey, salt, info); err != nil {
			return "", err
		}
	}

	// Advance the receiving chain to the correct message number
	for rs.RecvMsgNum < msg.Header.MsgNum-1 {
		msgKey, nextChainKey := ratchetStep(rs.RecvChainKey, salt, info)
		rs.RecvChainKey = nextChainKey
		rs.RecvMsgNum++

		// Store the message key for the skipped message
		if rs.skippedMsgKeyMap[peerKeyStr] == nil {
			rs.skippedMsgKeyMap[peerKeyStr] = make(map[uint32][]byte)
		}
		rs.skippedMsgKeyMap[peerKeyStr][rs.RecvMsgNum] = msgKey
	}

	// Derive the message key for decryption
	messageKey, nextChainKey := ratchetStep(rs.RecvChainKey, salt, info)
	rs.RecvChainKey = nextChainKey
	rs.RecvMsgNum++

	// Decrypt the message with AES-GCM
	data, err := base64.StdEncoding.DecodeString(msg.CipherText)
	if err != nil {
		return "", err
	}
	aesGcm := NewAesGcm(messageKey)
	plaintext, err := aesGcm.Decrypt(data)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
