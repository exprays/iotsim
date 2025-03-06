package blockchain

import (
	"encoding/json"
	"fmt"
	"time"
)

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

// SignTransaction adds a signature to a transaction
// In a real implementation, this would use proper cryptographic signing
func SignTransaction(tx *Transaction, privateKey []byte) error {
	if tx == nil {
		return fmt.Errorf("cannot sign nil transaction")
	}

	// This is a simplified signature - in a real implementation you'd use proper cryptography
	tx.Signature = []byte(fmt.Sprintf("signed-%s-%s", tx.Sender, tx.ID))
	return nil
}

// VerifyTransaction verifies a transaction's signature
// In a real implementation, this would use proper cryptographic verification
func VerifyTransaction(tx *Transaction, publicKey []byte) bool {
	if tx == nil || tx.Signature == nil {
		return false
	}

	// This is a simplified verification - in a real implementation you'd use proper cryptography
	expectedSig := []byte(fmt.Sprintf("signed-%s-%s", tx.Sender, tx.ID))

	// Simple comparison - not secure!
	matched := true
	if len(expectedSig) != len(tx.Signature) {
		matched = false
	} else {
		for i := range expectedSig {
			if expectedSig[i] != tx.Signature[i] {
				matched = false
				break
			}
		}
	}

	tx.Verified = matched
	return matched
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
	return calculateHash(block)
}
