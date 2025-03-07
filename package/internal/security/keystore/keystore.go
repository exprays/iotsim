package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"ranger/internal/blockchain"
	"ranger/internal/util/logger"

	"go.uber.org/zap"
	"golang.org/x/crypto/pbkdf2"
)

// KeyStoreEntry represents an encrypted key entry
type KeyStoreEntry struct {
	DeviceID         string    `json:"device_id"`
	EncryptedKey     []byte    `json:"encrypted_key"`
	IV               []byte    `json:"iv"`
	Salt             []byte    `json:"salt"`
	CreatedAt        time.Time `json:"created_at"`
	LastAccessedAt   time.Time `json:"last_accessed_at,omitempty"`
	AccessCount      int       `json:"access_count"`
	EncryptionMethod string    `json:"encryption_method"`
}

// KeyStore manages secure storage of cryptographic keys
type KeyStore struct {
	keys      map[string]*KeyStoreEntry
	mutex     sync.RWMutex
	masterKey []byte
	storePath string
	log       *logger.Logger
}

// KeyAccessAuditRecord represents a key access event for auditing
type KeyAccessAuditRecord struct {
	DeviceID     string    `json:"device_id"`
	AccessedAt   time.Time `json:"accessed_at"`
	AccessReason string    `json:"access_reason"`
	AccessedBy   string    `json:"accessed_by"`
}

var (
	ErrDeviceNotFound    = errors.New("device key not found in keystore")
	ErrEncryptionFailure = errors.New("failed to encrypt private key")
	ErrDecryptionFailure = errors.New("failed to decrypt private key")
)

// NewKeyStore creates a new keystore with the given master encryption key
func NewKeyStore(masterKeyHex string, storePath string) (*KeyStore, error) {
	log := logger.GetDefaultLogger().WithField("component", "key_store")

	// In production, the master key would be securely provided via HSM, KMS, or secure environment
	// For this implementation, we derive a key from the provided master key
	if len(masterKeyHex) < 32 {
		return nil, fmt.Errorf("master key must be at least 32 characters")
	}

	// Create a strong encryption key from the master key
	salt := []byte("iot-blockchain-salt") // In production, use a secure random salt
	masterKey := pbkdf2.Key([]byte(masterKeyHex), salt, 10000, 32, sha256.New)

	// Ensure the store directory exists
	if err := os.MkdirAll(filepath.Dir(storePath), 0700); err != nil {
		log.Error("Failed to create keystore directory", zap.Error(err))
		return nil, err
	}

	ks := &KeyStore{
		keys:      make(map[string]*KeyStoreEntry),
		masterKey: masterKey,
		storePath: storePath,
		log:       log,
	}

	// Load existing keys if available
	if err := ks.loadKeys(); err != nil {
		log.Warn("Unable to load existing keys, starting with empty keystore", zap.Error(err))
	}

	log.Info("Keystore initialized", zap.String("store_path", storePath))
	return ks, nil
}

// StorePrivateKey securely stores a device's private key
func (ks *KeyStore) StorePrivateKey(deviceID string, privateKeyPEM []byte) error {
	ks.log.Info("Storing private key", zap.String("device_id", deviceID))

	// Generate a random IV for AES-GCM
	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		ks.log.Error("Failed to generate IV", zap.Error(err))
		return ErrEncryptionFailure
	}

	// Generate a random salt for this specific key
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		ks.log.Error("Failed to generate salt", zap.Error(err))
		return ErrEncryptionFailure
	}

	// Create a unique encryption key for this device key by combining master key and device ID
	deviceKey := pbkdf2.Key(ks.masterKey, salt, 4096, 32, sha256.New)

	// Encrypt the private key
	block, err := aes.NewCipher(deviceKey)
	if err != nil {
		ks.log.Error("Failed to create cipher", zap.Error(err))
		return ErrEncryptionFailure
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		ks.log.Error("Failed to create GCM", zap.Error(err))
		return ErrEncryptionFailure
	}

	// Encrypt and authenticate the private key
	encryptedKey := aesgcm.Seal(nil, iv, privateKeyPEM, []byte(deviceID))

	// Store the encrypted key
	entry := &KeyStoreEntry{
		DeviceID:         deviceID,
		EncryptedKey:     encryptedKey,
		IV:               iv,
		Salt:             salt,
		CreatedAt:        time.Now(),
		EncryptionMethod: "AES-256-GCM",
	}

	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	ks.keys[deviceID] = entry

	// Save the updated keystore
	if err := ks.saveKeys(); err != nil {
		ks.log.Error("Failed to save keystore", zap.Error(err))
		return err
	}

	ks.log.Info("Private key stored successfully", zap.String("device_id", deviceID))
	return nil
}

// GetPrivateKey retrieves and decrypts a device's private key
func (ks *KeyStore) GetPrivateKey(deviceID string, reason string) (*ecdsa.PrivateKey, error) {
	ks.log.Debug("Retrieving private key", zap.String("device_id", deviceID), zap.String("reason", reason))

	ks.mutex.Lock()
	entry, exists := ks.keys[deviceID]
	if !exists {
		ks.mutex.Unlock()
		ks.log.Warn("Key not found", zap.String("device_id", deviceID))
		return nil, ErrDeviceNotFound
	}

	// Update access information
	entry.LastAccessedAt = time.Now()
	entry.AccessCount++
	ks.mutex.Unlock()

	// Record the access for audit purposes
	ks.recordAccess(deviceID, reason)

	// Derive the unique key for this device
	deviceKey := pbkdf2.Key(ks.masterKey, entry.Salt, 4096, 32, sha256.New)

	// Decrypt the private key
	block, err := aes.NewCipher(deviceKey)
	if err != nil {
		ks.log.Error("Failed to create cipher for decryption", zap.Error(err))
		return nil, ErrDecryptionFailure
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		ks.log.Error("Failed to create GCM for decryption", zap.Error(err))
		return nil, ErrDecryptionFailure
	}

	privateKeyPEM, err := aesgcm.Open(nil, entry.IV, entry.EncryptedKey, []byte(deviceID))
	if err != nil {
		ks.log.Error("Failed to decrypt key", zap.Error(err))
		return nil, ErrDecryptionFailure
	}

	// Parse the PEM encoded private key
	privateKey, err := blockchain.DecodePrivateKey(privateKeyPEM)
	if err != nil {
		ks.log.Error("Failed to decode private key PEM", zap.Error(err))
		return nil, err
	}

	return privateKey, nil
}

// DeleteKey removes a key from the store
func (ks *KeyStore) DeleteKey(deviceID string) error {
	ks.log.Info("Removing key from keystore", zap.String("device_id", deviceID))

	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	if _, exists := ks.keys[deviceID]; !exists {
		return ErrDeviceNotFound
	}

	delete(ks.keys, deviceID)

	if err := ks.saveKeys(); err != nil {
		ks.log.Error("Failed to save keystore after deletion", zap.Error(err))
		return err
	}

	ks.log.Info("Key deleted successfully", zap.String("device_id", deviceID))
	return nil
}

// RotateKey generates a new key for a device and updates the keystore
func (ks *KeyStore) RotateKey(deviceID string) ([]byte, error) {
	ks.log.Info("Rotating key for device", zap.String("device_id", deviceID))

	// Generate new key pair
	privateKey, publicKey, err := blockchain.GenerateKeyPair()
	if err != nil {
		ks.log.Error("Failed to generate new key pair", zap.Error(err))
		return nil, fmt.Errorf("failed to generate new key pair: %w", err)
	}

	// Encode keys
	privateKeyPEM, err := blockchain.EncodePrivateKey(privateKey)
	if err != nil {
		ks.log.Error("Failed to encode private key", zap.Error(err))
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}

	publicKeyPEM, err := blockchain.EncodePublicKey(publicKey)
	if err != nil {
		ks.log.Error("Failed to encode public key", zap.Error(err))
		return nil, fmt.Errorf("failed to encode public key: %w", err)
	}

	// Store new private key
	if err := ks.StorePrivateKey(deviceID, privateKeyPEM); err != nil {
		ks.log.Error("Failed to store rotated key", zap.Error(err))
		return nil, fmt.Errorf("failed to store rotated key: %w", err)
	}

	ks.log.Info("Key rotation completed successfully", zap.String("device_id", deviceID))
	return publicKeyPEM, nil
}

// GetKeyCount returns the number of keys in the store
func (ks *KeyStore) GetKeyCount() int {
	ks.mutex.RLock()
	defer ks.mutex.RUnlock()
	return len(ks.keys)
}

// loadKeys loads the keystore from disk
func (ks *KeyStore) loadKeys() error {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	data, err := os.ReadFile(ks.storePath)
	if err != nil {
		if os.IsNotExist(err) {
			ks.log.Info("No existing keystore found, creating new store")
			return nil
		}
		return err
	}

	// The stored data is encrypted with the master key
	// We need to decrypt it first (simplified here, in production use more layers)
	encryptedData := data

	// In a real implementation, you would decrypt the entire keystore file
	// For this demo, we'll assume the file contains JSON-encoded entries
	var entries map[string]*KeyStoreEntry
	if err := json.Unmarshal(encryptedData, &entries); err != nil {
		return err
	}

	ks.keys = entries
	ks.log.Info("Keystore loaded successfully", zap.Int("key_count", len(ks.keys)))
	return nil
}

// saveKeys saves the keystore to disk
func (ks *KeyStore) saveKeys() error {
	// In a real implementation, you would encrypt the entire keystore file
	// For this demo, we'll assume simple JSON encoding
	encryptedData, err := json.MarshalIndent(ks.keys, "", "  ")
	if err != nil {
		return err
	}

	// Write with secure permissions
	tempPath := ks.storePath + ".tmp"
	if err := os.WriteFile(tempPath, encryptedData, 0600); err != nil {
		return err
	}

	// Atomic replace
	return os.Rename(tempPath, ks.storePath)
}

// recordAccess records key access for audit purposes
func (ks *KeyStore) recordAccess(deviceID string, reason string) {
	record := KeyAccessAuditRecord{
		DeviceID:     deviceID,
		AccessedAt:   time.Now(),
		AccessReason: reason,
		AccessedBy:   "system", // In a real system, this would be the authenticated user or service
	}

	// In production, write to a secure audit log
	auditData, _ := json.Marshal(record)
	ks.log.Info("Key access recorded",
		zap.String("device_id", deviceID),
		zap.String("reason", reason),
		zap.ByteString("audit_record", auditData))
}
