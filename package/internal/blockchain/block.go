// with proper cryptographic signing and verification using industry-standard ECDSA (Elliptic Curve Digital Signature Algorithm) and SHA-256 (Secure Hash Algorithm 256-bit) functions. The code snippet below shows the implementation of the cryptographic functions for signing and verifying transactions, as well as generating and encoding ECDSA key pairs:

package blockchain

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// SignatureData stores the components of an ECDSA signature
type SignatureData struct {
	R *big.Int `json:"r"`
	S *big.Int `json:"s"`
}

// NewTransaction creates a new transaction with current timestamp
func NewTransaction(id, sender, recipient string, data []byte) Transaction {
	return Transaction{
		ID:        id,
		Sender:    sender,
		Recipient: recipient,
		Data:      data,
		Timestamp: time.Now(),
		Verified:  false,
	}
}

// GenerateKeyPair creates a new ECDSA key pair for signing and verification
func GenerateKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	return privateKey, &privateKey.PublicKey, nil
}

// EncodePrivateKey converts an ECDSA private key to PEM format
func EncodePrivateKey(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}

	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	pemEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: x509Encoded,
	})

	return pemEncoded, nil
}

// DecodePrivateKey converts a PEM formatted private key back to an ECDSA private key
func DecodePrivateKey(pemEncoded []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemEncoded)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	x509Encoded := block.Bytes
	privateKey, err := x509.ParseECPrivateKey(x509Encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privateKey, nil
}

// EncodePublicKey converts an ECDSA public key to PEM format
func EncodePublicKey(publicKey *ecdsa.PublicKey) ([]byte, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("public key is nil")
	}

	x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pemEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509EncodedPub,
	})

	return pemEncoded, nil
}

// DecodePublicKey converts a PEM formatted public key back to an ECDSA public key
func DecodePublicKey(pemEncoded []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemEncoded)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	genericPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	publicKey, ok := genericPublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}

	return publicKey, nil
}

// hashTransaction creates a SHA-256 hash of transaction data for signing
func hashTransaction(tx *Transaction) ([]byte, error) {
	// Create a version of the transaction without the signature for hashing
	txCopy := *tx
	txCopy.Signature = nil

	txData, err := json.Marshal(txCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal transaction: %w", err)
	}

	hash := sha256.Sum256(txData)
	return hash[:], nil
}

// SignTransaction signs a transaction using ECDSA
func SignTransaction(tx *Transaction, privateKey *ecdsa.PrivateKey) error {
	if tx == nil {
		return fmt.Errorf("cannot sign nil transaction")
	}

	if privateKey == nil {
		return fmt.Errorf("private key is nil")
	}

	// Hash the transaction data
	hash, err := hashTransaction(tx)
	if err != nil {
		return fmt.Errorf("failed to hash transaction: %w", err)
	}

	// Sign the hash with the private key
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash)
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Store the signature components
	signature := SignatureData{
		R: r,
		S: s,
	}

	// Convert the signature to JSON
	signatureBytes, err := json.Marshal(signature)
	if err != nil {
		return fmt.Errorf("failed to marshal signature: %w", err)
	}

	tx.Signature = signatureBytes
	return nil
}

// VerifyTransaction verifies a transaction's signature using ECDSA
func VerifyTransaction(tx *Transaction, publicKey *ecdsa.PublicKey) bool {
	if tx == nil || tx.Signature == nil || publicKey == nil {
		return false
	}

	// Unmarshal the signature
	var signature SignatureData
	if err := json.Unmarshal(tx.Signature, &signature); err != nil {
		return false
	}

	// Create a hash of the transaction (excluding signature)
	txCopy := *tx
	txCopy.Signature = nil

	hash, err := hashTransaction(&txCopy)
	if err != nil {
		return false
	}

	// Verify the signature against the hash
	valid := ecdsa.Verify(publicKey, hash, signature.R, signature.S)

	tx.Verified = valid
	return valid
}

// MarshalBlock serializes a block to JSON
func MarshalBlock(block Block) ([]byte, error) {
	return json.Marshal(block)
}

// UnmarshalBlock deserializes JSON data into a Block
func UnmarshalBlock(data []byte) (*Block, error) {
	var block Block
	err := json.Unmarshal(data, &block)
	if err != nil {
		return nil, err
	}
	return &block, nil
}

// CalculateBlockHash recalculates and returns the hash for a given block
func CalculateBlockHash(block Block) string {
	return computeBlockHash(block)
}

// Helper function to calculate a secure hash of a block
func computeBlockHash(block Block) string {
	// Create a JSON representation of the block header
	header := struct {
		PrevHash   string    `json:"prevHash"`
		MerkleRoot string    `json:"merkleRoot"`
		Timestamp  time.Time `json:"timestamp"`
		Nonce      uint64    `json:"nonce"`
	}{
		PrevHash:   block.PrevHash,
		MerkleRoot: calculateMerkleRoot(block.Transactions),
		Timestamp:  block.Timestamp,
		Nonce:      block.Nonce,
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return ""
	}

	hash := sha256.Sum256(headerBytes)
	return fmt.Sprintf("%x", hash)
}

// calculateMerkleRoot computes the Merkle root of the transactions
func calculateMerkleRoot(transactions []Transaction) string {
	if len(transactions) == 0 {
		return ""
	}

	// Generate hashes for all transactions
	hashes := make([][]byte, len(transactions))
	for i, tx := range transactions {
		txBytes, err := json.Marshal(tx)
		if err != nil {
			continue
		}
		hash := sha256.Sum256(txBytes)
		hashes[i] = hash[:]
	}

	// Build the Merkle tree
	for len(hashes) > 1 {
		if len(hashes)%2 != 0 {
			// Duplicate the last hash if we have an odd number
			hashes = append(hashes, hashes[len(hashes)-1])
		}

		nextLevel := make([][]byte, len(hashes)/2)
		for i := 0; i < len(hashes); i += 2 {
			combined := append(hashes[i], hashes[i+1]...)
			hash := sha256.Sum256(combined)
			nextLevel[i/2] = hash[:]
		}

		hashes = nextLevel
	}

	return fmt.Sprintf("%x", hashes[0])
}
