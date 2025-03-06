package blockchain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Transaction represents data sent to the blockchain
type Transaction struct {
	ID        string    `json:"id"`
	Sender    string    `json:"sender"`
	Recipient string    `json:"recipient"`
	Data      []byte    `json:"data"`
	Timestamp time.Time `json:"timestamp"`
	Signature []byte    `json:"signature"`
	Verified  bool      `json:"verified"`
}

// Block represents a block in the blockchain
type Block struct {
	Index        uint64        `json:"index"`
	Timestamp    time.Time     `json:"timestamp"`
	Transactions []Transaction `json:"transactions"`
	Hash         string        `json:"hash"`
	PrevHash     string        `json:"prevHash"`
	Nonce        uint64        `json:"nonce"`
}

// Blockchain represents the main blockchain data structure
type Blockchain struct {
	Chain               []Block
	PendingTransactions []Transaction
	Difficulty          uint8
	miningReward        float64
	mutex               sync.RWMutex
}

// NewBlockchain creates and initializes a new blockchain with genesis block
func NewBlockchain(difficulty uint8, miningReward float64) *Blockchain {
	bc := &Blockchain{
		Chain:               make([]Block, 0),
		PendingTransactions: make([]Transaction, 0),
		Difficulty:          difficulty,
		miningReward:        miningReward,
	}

	// Create genesis block
	genesisBlock := Block{
		Index:        0,
		Timestamp:    time.Now(),
		Transactions: []Transaction{},
		Hash:         "",
		PrevHash:     "0",
		Nonce:        0,
	}

	genesisBlock.Hash = calculateHash(genesisBlock)
	bc.Chain = append(bc.Chain, genesisBlock)
	return bc
}

// CalculateHash generates a SHA256 hash from a block
func calculateHash(block Block) string {
	record := fmt.Sprintf("%d%s%s%d",
		block.Index,
		block.Timestamp.String(),
		block.PrevHash,
		block.Nonce)

	for _, tx := range block.Transactions {
		record += tx.ID
	}

	h := sha256.New()
	h.Write([]byte(record))
	return hex.EncodeToString(h.Sum(nil))
}

// MineBlock mines a new block with proof of work
func (bc *Blockchain) MineBlock(minerAddress string) (*Block, error) {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	if len(bc.PendingTransactions) == 0 {
		return nil, fmt.Errorf("no transactions to mine")
	}

	lastBlock := bc.Chain[len(bc.Chain)-1]

	newBlock := Block{
		Index:        lastBlock.Index + 1,
		Timestamp:    time.Now(),
		Transactions: bc.PendingTransactions,
		PrevHash:     lastBlock.Hash,
		Nonce:        0,
	}

	// Add mining reward transaction
	rewardTx := Transaction{
		ID:        fmt.Sprintf("reward-%d", time.Now().UnixNano()),
		Sender:    "SYSTEM",
		Recipient: minerAddress,
		Data:      []byte(fmt.Sprintf("Mining reward: %.2f", bc.miningReward)),
		Timestamp: time.Now(),
		Verified:  true,
	}

	newBlock.Transactions = append(newBlock.Transactions, rewardTx)

	// Proof of work - find a hash with leading zeros based on difficulty
	prefix := make([]byte, bc.Difficulty)
	targetPrefix := string(prefix)

	for {
		newBlock.Hash = calculateHash(newBlock)
		if newBlock.Hash[:bc.Difficulty] == targetPrefix {
			break
		}
		newBlock.Nonce++
	}

	bc.Chain = append(bc.Chain, newBlock)
	bc.PendingTransactions = []Transaction{}

	return &newBlock, nil
}

// AddTransaction adds a new transaction to pending transactions
func (bc *Blockchain) AddTransaction(tx Transaction) error {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	// Basic validation
	if tx.Sender == "" || tx.Recipient == "" {
		return fmt.Errorf("invalid transaction: missing sender or recipient")
	}

	// In a real implementation, you'd verify the signature here

	bc.PendingTransactions = append(bc.PendingTransactions, tx)
	return nil
}

// ValidateChain verifies the integrity of the entire blockchain
func (bc *Blockchain) ValidateChain() bool {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()

	for i := 1; i < len(bc.Chain); i++ {
		currentBlock := bc.Chain[i]
		previousBlock := bc.Chain[i-1]

		// Check hash validity
		if currentBlock.Hash != calculateHash(currentBlock) {
			return false
		}

		// Check chain continuity
		if currentBlock.PrevHash != previousBlock.Hash {
			return false
		}
	}

	return true
}

// GetBalance returns the balance of an address by scanning the blockchain
func (bc *Blockchain) GetBalance(address string) float64 {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()

	balance := 0.0

	for _, block := range bc.Chain {
		for _, tx := range block.Transactions {
			if tx.Recipient == address {
				// In a real implementation, you'd parse the value from tx.Data
				balance += 1.0 // Simplified
			}

			if tx.Sender == address {
				balance -= 1.0 // Simplified
			}
		}
	}

	return balance
}

// GetBlockByHash retrieves a block by its hash
func (bc *Blockchain) GetBlockByHash(hash string) (*Block, error) {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()

	for _, block := range bc.Chain {
		if block.Hash == hash {
			return &block, nil
		}
	}

	return nil, fmt.Errorf("block not found with hash: %s", hash)
}

// GetTransactionsByAddress returns all transactions involving an address
func (bc *Blockchain) GetTransactionsByAddress(address string) []Transaction {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()

	var transactions []Transaction

	for _, block := range bc.Chain {
		for _, tx := range block.Transactions {
			if tx.Sender == address || tx.Recipient == address {
				transactions = append(transactions, tx)
			}
		}
	}

	return transactions
}

// GetChainLength returns the current length of the blockchain
func (bc *Blockchain) GetChainLength() int {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()
	return len(bc.Chain)
}

// GetPendingTransactionsCount returns the number of pending transactions
func (bc *Blockchain) GetPendingTransactionsCount() int {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()
	return len(bc.PendingTransactions)
}
