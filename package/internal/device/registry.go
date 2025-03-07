package device

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"ranger/internal/blockchain"
	"ranger/internal/security/keystore"
	"ranger/internal/util/logger"

	"go.uber.org/zap"
)

// DeviceType represents the type of IoT device
type DeviceType string

const (
	ESP8266 DeviceType = "ESP8266"
	Generic DeviceType = "Generic"
)

// DeviceStatus represents the current status of a device
type DeviceStatus string

const (
	Online    DeviceStatus = "Online"
	Offline   DeviceStatus = "Offline"
	Suspended DeviceStatus = "Suspended"
	Unknown   DeviceStatus = "Unknown"
)

// Device represents an IoT device in the system
type Device struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Type            DeviceType             `json:"type"`
	Status          DeviceStatus           `json:"status"`
	LastSeen        time.Time              `json:"lastSeen"`
	RegisteredAt    time.Time              `json:"registeredAt"`
	APIKey          string                 `json:"apiKey"`
	BlockchainAddr  string                 `json:"blockchainAddr"`
	PublicKey       []byte                 `json:"publicKey"`
	Capabilities    []string               `json:"capabilities"`
	Metadata        map[string]interface{} `json:"metadata"`
	FirmwareVersion string                 `json:"firmwareVersion"`
	IPAddress       string                 `json:"ipAddress,omitempty"`
}

// DeviceRegistry manages IoT devices in the system
type DeviceRegistry struct {
	devices      map[string]*Device
	apiKeyIndex  map[string]string // maps API keys to device IDs
	mutex        sync.RWMutex
	eventChannel chan DeviceEvent
	log          *logger.Logger
	keyStore     *keystore.KeyStore
}

// DeviceEvent represents events related to devices
type DeviceEvent struct {
	Type      string    `json:"type"`
	DeviceID  string    `json:"deviceId"`
	Timestamp time.Time `json:"timestamp"`
	Data      any       `json:"data,omitempty"`
}

// NewDeviceRegistry creates a new device registry
func NewDeviceRegistry(keyStorePath string, masterKey string) *DeviceRegistry {
	log := logger.GetDefaultLogger().WithField("component", "device_registry")
	log.Info("Creating new device registry")

	// Initialize key store
	keyStore, err := keystore.NewKeyStore(masterKey, keyStorePath)
	if err != nil {
		log.Error("Failed to initialize key store, running without secure key storage", zap.Error(err))
		// Continue without keystore in this case
	}

	return &DeviceRegistry{
		devices:      make(map[string]*Device),
		apiKeyIndex:  make(map[string]string),
		eventChannel: make(chan DeviceEvent, 100),
		log:          log,
		keyStore:     keyStore,
	}
}

// RegisterDevice adds a new device to the registry
func (r *DeviceRegistry) RegisterDevice(name string, deviceType DeviceType, capabilities []string, metadata map[string]interface{}) (*Device, error) {
	r.log.Info("Registering new device",
		zap.String("name", name),
		zap.String("type", string(deviceType)))

	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Generate unique device ID
	deviceID, err := generateID()
	if err != nil {
		r.log.Error("Failed to generate device ID", zap.Error(err))
		return nil, fmt.Errorf("failed to generate device ID: %w", err)
	}

	// Generate API key for device authentication
	apiKey, err := generateAPIKey()
	if err != nil {
		r.log.Error("Failed to generate API key", zap.Error(err))
		return nil, fmt.Errorf("failed to generate API key: %w", err)
	}

	// Generate key pair for blockchain transactions
	privateKey, publicKey, err := blockchain.GenerateKeyPair()
	if err != nil {
		r.log.Error("Failed to generate blockchain keys", zap.Error(err))
		return nil, fmt.Errorf("failed to generate blockchain keys: %w", err)
	}

	// Store private key securely (in a real system, this should be handled with HSM or similar)
	privateKeyPEM, err := blockchain.EncodePrivateKey(privateKey)
	if err != nil {
		r.log.Error("Failed to encode private key", zap.Error(err))
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}

	publicKeyPEM, err := blockchain.EncodePublicKey(publicKey)
	if err != nil {
		r.log.Error("Failed to encode public key", zap.Error(err))
		return nil, fmt.Errorf("failed to encode public key: %w", err)
	}

	// Generate blockchain address from public key (simplified)
	blockchainAddr := fmt.Sprintf("0x%s", hex.EncodeToString(publicKeyPEM)[:40])

	now := time.Now()
	device := &Device{
		ID:             deviceID,
		Name:           name,
		Type:           deviceType,
		Status:         Offline,
		LastSeen:       now,
		RegisteredAt:   now,
		APIKey:         apiKey,
		BlockchainAddr: blockchainAddr,
		PublicKey:      publicKeyPEM,
		Capabilities:   capabilities,
		Metadata:       metadata,
	}

	// Store private key securely in key vault
	if r.keyStore != nil {
		if err := r.keyStore.StorePrivateKey(deviceID, privateKeyPEM); err != nil {
			r.log.Error("Failed to store private key securely",
				zap.String("device_id", deviceID),
				zap.Error(err))
			return nil, fmt.Errorf("failed to store private key: %w", err)
		}
		r.log.Info("Device private key stored securely", zap.String("device_id", deviceID))
	} else {
		r.log.Warn("Key store not available, unable to securely store private key",
			zap.String("device_id", deviceID))
		// In a production system, this should be a fatal error
	}

	r.devices[deviceID] = device
	r.apiKeyIndex[apiKey] = deviceID

	// Publish registration event
	r.eventChannel <- DeviceEvent{
		Type:      "DEVICE_REGISTERED",
		DeviceID:  deviceID,
		Timestamp: now,
		Data:      device,
	}

	r.log.Info("Device registered successfully",
		zap.String("device_id", deviceID),
		zap.String("blockchain_addr", blockchainAddr))

	return device, nil
}

// GetDeviceByID retrieves a device by its ID
func (r *DeviceRegistry) GetDeviceByID(id string) (*Device, error) {
	r.log.Debug("Looking up device by ID", zap.String("device_id", id))

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	device, exists := r.devices[id]
	if !exists {
		r.log.Warn("Device not found", zap.String("device_id", id))
		return nil, errors.New("device not found")
	}

	return device, nil
}

// GetDeviceByAPIKey retrieves a device by its API key
func (r *DeviceRegistry) GetDeviceByAPIKey(apiKey string) (*Device, error) {
	r.log.Debug("Looking up device by API key")

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	deviceID, exists := r.apiKeyIndex[apiKey]
	if !exists {
		r.log.Warn("Invalid API key used for authentication")
		return nil, errors.New("invalid API key")
	}

	device, exists := r.devices[deviceID]
	if !exists {
		r.log.Error("Device found in API index but missing in devices map",
			zap.String("device_id", deviceID))
		return nil, errors.New("device not found")
	}

	return device, nil
}

// GetDeviceByBlockchainAddr retrieves a device by its blockchain address
func (r *DeviceRegistry) GetDeviceByBlockchainAddr(blockchainAddr string) (*Device, error) {
	r.log.Debug("Looking up device by blockchain address",
		zap.String("blockchain_addr", blockchainAddr))

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for _, device := range r.devices {
		if device.BlockchainAddr == blockchainAddr {
			return device, nil
		}
	}

	r.log.Warn("Device not found by blockchain address",
		zap.String("blockchain_addr", blockchainAddr))
	return nil, errors.New("device not found")
}

// UpdateDeviceStatus updates a device's status
func (r *DeviceRegistry) UpdateDeviceStatus(id string, status DeviceStatus) error {
	r.log.Debug("Updating device status",
		zap.String("device_id", id),
		zap.String("status", string(status)))

	r.mutex.Lock()
	defer r.mutex.Unlock()

	device, exists := r.devices[id]
	if !exists {
		r.log.Warn("Attempted to update status of non-existent device", zap.String("device_id", id))
		return errors.New("device not found")
	}

	oldStatus := device.Status
	device.Status = status
	device.LastSeen = time.Now()

	// Publish status change event
	r.eventChannel <- DeviceEvent{
		Type:      "DEVICE_STATUS_CHANGED",
		DeviceID:  id,
		Timestamp: time.Now(),
		Data: map[string]string{
			"oldStatus": string(oldStatus),
			"newStatus": string(status),
		},
	}

	r.log.Info("Device status updated",
		zap.String("device_id", id),
		zap.String("old_status", string(oldStatus)),
		zap.String("new_status", string(status)))

	return nil
}

// UpdateDeviceMetadata updates a device's metadata
func (r *DeviceRegistry) UpdateDeviceMetadata(id string, metadata map[string]interface{}) error {
	r.log.Debug("Updating device metadata", zap.String("device_id", id))

	r.mutex.Lock()
	defer r.mutex.Unlock()

	device, exists := r.devices[id]
	if !exists {
		r.log.Warn("Attempted to update metadata of non-existent device", zap.String("device_id", id))
		return errors.New("device not found")
	}

	// Merge metadata
	if device.Metadata == nil {
		device.Metadata = metadata
	} else {
		for k, v := range metadata {
			device.Metadata[k] = v
		}
	}

	// Publish metadata update event
	r.eventChannel <- DeviceEvent{
		Type:      "DEVICE_METADATA_UPDATED",
		DeviceID:  id,
		Timestamp: time.Now(),
	}

	r.log.Info("Device metadata updated", zap.String("device_id", id))

	return nil
}

// UpdateFirmware updates a device's firmware version
func (r *DeviceRegistry) UpdateFirmware(id string, version string) error {
	r.log.Debug("Updating device firmware",
		zap.String("device_id", id),
		zap.String("version", version))

	r.mutex.Lock()
	defer r.mutex.Unlock()

	device, exists := r.devices[id]
	if !exists {
		r.log.Warn("Attempted to update firmware of non-existent device", zap.String("device_id", id))
		return errors.New("device not found")
	}

	oldVersion := device.FirmwareVersion
	device.FirmwareVersion = version

	// Publish firmware update event
	r.eventChannel <- DeviceEvent{
		Type:      "DEVICE_FIRMWARE_UPDATED",
		DeviceID:  id,
		Timestamp: time.Now(),
		Data: map[string]string{
			"oldVersion": oldVersion,
			"newVersion": version,
		},
	}

	r.log.Info("Device firmware updated",
		zap.String("device_id", id),
		zap.String("old_version", oldVersion),
		zap.String("new_version", version))

	return nil
}

// RemoveDevice removes a device from the registry
func (r *DeviceRegistry) RemoveDevice(id string) error {
	r.log.Info("Removing device", zap.String("device_id", id))

	r.mutex.Lock()
	defer r.mutex.Unlock()

	device, exists := r.devices[id]
	if !exists {
		r.log.Warn("Attempted to remove non-existent device", zap.String("device_id", id))
		return errors.New("device not found")
	}

	// Clean up API key index
	delete(r.apiKeyIndex, device.APIKey)
	delete(r.devices, id)

	// Publish device removed event
	r.eventChannel <- DeviceEvent{
		Type:      "DEVICE_REMOVED",
		DeviceID:  id,
		Timestamp: time.Now(),
	}

	r.log.Info("Device removed successfully", zap.String("device_id", id))

	return nil
}

// RemoveDeviceWithKeys removes a device from the registry and cleans up keys
func (r *DeviceRegistry) RemoveDeviceWithKeys(id string) error {
	r.log.Info("Removing device with keys", zap.String("device_id", id))

	// First remove the device from the registry
	if err := r.RemoveDevice(id); err != nil {
		return err
	}

	// Then remove the keys from key store
	if r.keyStore != nil {
		if err := r.keyStore.DeleteKey(id); err != nil {
			r.log.Warn("Failed to remove device key",
				zap.String("device_id", id),
				zap.Error(err))
			// Don't fail the operation if key deletion fails
		}
	}

	return nil
}

// ListDevices returns a list of all registered devices
func (r *DeviceRegistry) ListDevices() []*Device {
	r.log.Debug("Listing all devices")

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	devices := make([]*Device, 0, len(r.devices))
	for _, device := range r.devices {
		devices = append(devices, device)
	}

	r.log.Debug("Device list retrieved", zap.Int("count", len(devices)))

	return devices
}

// UpdateLastSeen updates the last time a device was seen active
func (r *DeviceRegistry) UpdateLastSeen(deviceID string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if device, exists := r.devices[deviceID]; exists {
		device.LastSeen = time.Now()
		r.log.Debug("Updated device last seen timestamp", zap.String("device_id", deviceID))
	} else {
		r.log.Warn("Attempted to update last seen for non-existent device", zap.String("device_id", deviceID))
	}
}

// GetDeviceCount returns the number of registered devices
func (r *DeviceRegistry) GetDeviceCount() int {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	count := len(r.devices)
	r.log.Debug("Retrieved device count", zap.Int("count", count))

	return count
}

// EventChannel returns the channel for device events
func (r *DeviceRegistry) EventChannel() <-chan DeviceEvent {
	return r.eventChannel
}

// SaveRegistry saves the registry to a JSON file
func (r *DeviceRegistry) SaveRegistry(path string) error {
	r.log.Info("Saving device registry to file", zap.String("path", path))

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	start := time.Now()

	data, err := json.MarshalIndent(r.devices, "", "  ")
	if err != nil {
		r.log.Error("Failed to marshal device registry", zap.Error(err))
		return fmt.Errorf("failed to marshal device registry: %w", err)
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		r.log.Error("Failed to create directory for registry file",
			zap.String("directory", dir),
			zap.Error(err))
		return fmt.Errorf("failed to create directory for registry file: %w", err)
	}

	// Write to file (atomic write pattern)
	tempFile := path + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		r.log.Error("Failed to write registry to temporary file",
			zap.String("temp_file", tempFile),
			zap.Error(err))
		return fmt.Errorf("failed to write registry to temporary file: %w", err)
	}

	// Rename to target file (atomic operation)
	if err := os.Rename(tempFile, path); err != nil {
		r.log.Error("Failed to save registry file",
			zap.String("temp_file", tempFile),
			zap.String("target_file", path),
			zap.Error(err))
		return fmt.Errorf("failed to save registry file: %w", err)
	}

	elapsed := time.Since(start)
	r.log.Info("Device registry saved successfully",
		zap.String("path", path),
		zap.Int("device_count", len(r.devices)),
		zap.Duration("elapsed_time", elapsed))

	return nil
}

// LoadRegistry loads the registry from a JSON file
func (r *DeviceRegistry) LoadRegistry(path string) error {
	r.log.Info("Loading device registry from file", zap.String("path", path))

	start := time.Now()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			r.log.Warn("Registry file does not exist, will create when saving", zap.String("path", path))
			return nil // Not an error if file doesn't exist yet
		}
		r.log.Error("Failed to read registry file", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("failed to read registry file: %w", err)
	}

	// Unmarshal the JSON data
	var devices map[string]*Device
	if err := json.Unmarshal(data, &devices); err != nil {
		r.log.Error("Failed to parse registry data", zap.Error(err))
		return fmt.Errorf("failed to parse registry data: %w", err)
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Clear existing data
	r.devices = make(map[string]*Device)
	r.apiKeyIndex = make(map[string]string)

	// Load devices and rebuild API key index
	for id, device := range devices {
		r.devices[id] = device
		r.apiKeyIndex[device.APIKey] = id
	}

	elapsed := time.Since(start)
	r.log.Info("Device registry loaded successfully",
		zap.String("path", path),
		zap.Int("device_count", len(r.devices)),
		zap.Duration("elapsed_time", elapsed))

	return nil
}

// GetPrivateKeyForDevice retrieves a device's private key for signing transactions
func (r *DeviceRegistry) GetPrivateKeyForDevice(deviceID string, reason string) (*ecdsa.PrivateKey, error) {
	if r.keyStore == nil {
		return nil, fmt.Errorf("key store not available")
	}

	// First check if device exists
	r.mutex.RLock()
	_, exists := r.devices[deviceID]
	r.mutex.RUnlock()

	if !exists {
		return nil, errors.New("device not found")
	}

	// Then retrieve the key from secure storage
	return r.keyStore.GetPrivateKey(deviceID, reason)
}

// RotateDeviceKey generates a new key pair for a device
func (r *DeviceRegistry) RotateDeviceKey(deviceID string) ([]byte, error) {
	r.log.Info("Rotating key for device", zap.String("device_id", deviceID))

	r.mutex.Lock()
	defer r.mutex.Unlock()

	device, exists := r.devices[deviceID]
	if !exists {
		r.log.Warn("Attempted to rotate key for non-existent device", zap.String("device_id", deviceID))
		return nil, errors.New("device not found")
	}

	if r.keyStore == nil {
		r.log.Error("Key store not available", zap.String("device_id", deviceID))
		return nil, errors.New("key store not available")
	}

	// Rotate the key in the key store
	publicKeyPEM, err := r.keyStore.RotateKey(deviceID)
	if err != nil {
		r.log.Error("Failed to rotate key", zap.String("device_id", deviceID), zap.Error(err))
		return nil, fmt.Errorf("failed to rotate key: %w", err)
	}

	// Update device with new public key
	device.PublicKey = publicKeyPEM

	// Publish key rotation event
	r.eventChannel <- DeviceEvent{
		Type:      "DEVICE_KEY_ROTATED",
		DeviceID:  deviceID,
		Timestamp: time.Now(),
	}

	r.log.Info("Device key rotated successfully", zap.String("device_id", deviceID))
	return publicKeyPEM, nil
}

// Helper functions

// generateID creates a unique ID for a device
func generateID() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// generateAPIKey creates a secure API key for device authentication
func generateAPIKey() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// generateBlockchainAddress creates a blockchain address for the device
func generateBlockchainAddress() (string, error) {
	b := make([]byte, 20)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("0x%x", b), nil
}
