package device

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
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
}

// DeviceEvent represents events related to devices
type DeviceEvent struct {
	Type      string    `json:"type"`
	DeviceID  string    `json:"deviceId"`
	Timestamp time.Time `json:"timestamp"`
	Data      any       `json:"data,omitempty"`
}

// NewDeviceRegistry creates a new device registry
func NewDeviceRegistry() *DeviceRegistry {
	return &DeviceRegistry{
		devices:      make(map[string]*Device),
		apiKeyIndex:  make(map[string]string),
		eventChannel: make(chan DeviceEvent, 100),
	}
}

// RegisterDevice adds a new device to the registry
func (r *DeviceRegistry) RegisterDevice(name string, deviceType DeviceType, capabilities []string, metadata map[string]interface{}) (*Device, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Generate unique device ID
	deviceID, err := generateID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate device ID: %w", err)
	}

	// Generate API key for device authentication
	apiKey, err := generateAPIKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate API key: %w", err)
	}

	// Generate blockchain address for this device
	blockchainAddr, err := generateBlockchainAddress()
	if err != nil {
		return nil, fmt.Errorf("failed to generate blockchain address: %w", err)
	}

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
		Capabilities:   capabilities,
		Metadata:       metadata,
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

	return device, nil
}

// GetDeviceByID retrieves a device by its ID
func (r *DeviceRegistry) GetDeviceByID(id string) (*Device, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	device, exists := r.devices[id]
	if !exists {
		return nil, errors.New("device not found")
	}

	return device, nil
}

// GetDeviceByAPIKey retrieves a device by its API key
func (r *DeviceRegistry) GetDeviceByAPIKey(apiKey string) (*Device, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	deviceID, exists := r.apiKeyIndex[apiKey]
	if !exists {
		return nil, errors.New("invalid API key")
	}

	device, exists := r.devices[deviceID]
	if !exists {
		return nil, errors.New("device not found")
	}

	return device, nil
}

// UpdateDeviceStatus updates a device's status
func (r *DeviceRegistry) UpdateDeviceStatus(id string, status DeviceStatus) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	device, exists := r.devices[id]
	if !exists {
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

	return nil
}

// UpdateDeviceMetadata updates a device's metadata
func (r *DeviceRegistry) UpdateDeviceMetadata(id string, metadata map[string]interface{}) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	device, exists := r.devices[id]
	if !exists {
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

	return nil
}

// UpdateFirmware updates a device's firmware version
func (r *DeviceRegistry) UpdateFirmware(id string, version string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	device, exists := r.devices[id]
	if !exists {
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

	return nil
}

// RemoveDevice removes a device from the registry
func (r *DeviceRegistry) RemoveDevice(id string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	device, exists := r.devices[id]
	if !exists {
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

	return nil
}

// ListDevices returns a list of all registered devices
func (r *DeviceRegistry) ListDevices() []*Device {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	devices := make([]*Device, 0, len(r.devices))
	for _, device := range r.devices {
		devices = append(devices, device)
	}

	return devices
}

// GetDeviceCount returns the number of registered devices
func (r *DeviceRegistry) GetDeviceCount() int {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return len(r.devices)
}

// EventChannel returns the channel for device events
func (r *DeviceRegistry) EventChannel() <-chan DeviceEvent {
	return r.eventChannel
}

// SaveRegistry saves the registry to a JSON file
func (r *DeviceRegistry) SaveRegistry(path string) error {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	data, err := json.MarshalIndent(r.devices, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal device registry: %w", err)
	}

	// In a real implementation, you would write this to a file
	// For now, we'll just log the output (simplified)
	fmt.Printf("Would save registry to %s with %d bytes\n", path, len(data))
	return nil
}

// LoadRegistry loads the registry from a JSON file
func (r *DeviceRegistry) LoadRegistry(path string) error {
	// In a real implementation, you would read from a file
	// This is a simplified version for demonstration
	return fmt.Errorf("not implemented")
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
