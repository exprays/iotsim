package device

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// ESP8266Device represents a specialized ESP8266 device
type ESP8266Device struct {
	Device         *Device
	WifiSSID       string
	WifiConnected  bool
	SensorReadings map[string]float64
	LEDState       bool
	ButtonState    bool
	LastReading    time.Time
}

// ESP8266Manager manages ESP8266 devices
type ESP8266Manager struct {
	registry     *DeviceRegistry
	deviceStates map[string]*ESP8266Device
	stateMutex   sync.RWMutex
}

// NewESP8266Manager creates a new ESP8266 manager
func NewESP8266Manager(registry *DeviceRegistry) *ESP8266Manager {
	return &ESP8266Manager{
		registry:     registry,
		deviceStates: make(map[string]*ESP8266Device),
	}
}

// RegisterESP8266 registers a new ESP8266 device
func (m *ESP8266Manager) RegisterESP8266(name string, wifiSSID string) (*ESP8266Device, error) {
	// Default capabilities for ESP8266
	capabilities := []string{"temperature", "humidity", "led_control", "button"}

	// Default metadata for ESP8266
	metadata := map[string]interface{}{
		"wifi_ssid":     wifiSSID,
		"pin_led":       "D2", // Default LED pin
		"pin_button":    "D1", // Default button pin
		"poll_interval": 30,   // Default poll interval in seconds
	}

	// Register the base device
	device, err := m.registry.RegisterDevice(name, ESP8266, capabilities, metadata)
	if err != nil {
		return nil, err
	}

	// Create ESP8266 specific state
	esp := &ESP8266Device{
		Device:         device,
		WifiSSID:       wifiSSID,
		WifiConnected:  false,
		SensorReadings: make(map[string]float64),
		LEDState:       false,
		ButtonState:    false,
		LastReading:    time.Now(),
	}

	m.stateMutex.Lock()
	m.deviceStates[device.ID] = esp
	m.stateMutex.Unlock()

	return esp, nil
}

// GetESP8266 retrieves an ESP8266 device by ID
func (m *ESP8266Manager) GetESP8266(id string) (*ESP8266Device, error) {
	m.stateMutex.RLock()
	defer m.stateMutex.RUnlock()

	esp, exists := m.deviceStates[id]
	if !exists {
		return nil, errors.New("ESP8266 device not found")
	}

	return esp, nil
}

// UpdateSensorReading updates a sensor reading for an ESP8266 device
func (m *ESP8266Manager) UpdateSensorReading(id string, sensorType string, value float64) error {
	m.stateMutex.Lock()
	defer m.stateMutex.Unlock()

	esp, exists := m.deviceStates[id]
	if !exists {
		return errors.New("ESP8266 device not found")
	}

	esp.SensorReadings[sensorType] = value
	esp.LastReading = time.Now()

	// Update device status to Online
	m.registry.UpdateDeviceStatus(id, Online)

	return nil
}

// SetLEDState sets the LED state for an ESP8266 device
func (m *ESP8266Manager) SetLEDState(id string, state bool) error {
	m.stateMutex.Lock()
	defer m.stateMutex.Unlock()

	esp, exists := m.deviceStates[id]
	if !exists {
		return errors.New("ESP8266 device not found")
	}

	esp.LEDState = state

	// Update metadata to reflect LED state
	m.registry.UpdateDeviceMetadata(id, map[string]interface{}{
		"led_state": state,
	})

	return nil
}

// UpdateWiFiStatus updates the WiFi connection status for an ESP8266 device
func (m *ESP8266Manager) UpdateWiFiStatus(id string, connected bool, ipAddress string) error {
	m.stateMutex.Lock()
	defer m.stateMutex.Unlock()

	esp, exists := m.deviceStates[id]
	if !exists {
		return errors.New("ESP8266 device not found")
	}

	esp.WifiConnected = connected

	// Update the base device with new information
	device, err := m.registry.GetDeviceByID(id)
	if err != nil {
		return err
	}

	device.IPAddress = ipAddress

	// Update metadata
	m.registry.UpdateDeviceMetadata(id, map[string]interface{}{
		"wifi_connected": connected,
		"ip_address":     ipAddress,
	})

	return nil
}

// GetButtonState gets the button state for an ESP8266 device
func (m *ESP8266Manager) GetButtonState(id string) (bool, error) {
	m.stateMutex.RLock()
	defer m.stateMutex.RUnlock()

	esp, exists := m.deviceStates[id]
	if !exists {
		return false, errors.New("ESP8266 device not found")
	}

	return esp.ButtonState, nil
}

// UpdateButtonState updates the button state for an ESP8266 device
func (m *ESP8266Manager) UpdateButtonState(id string, pressed bool) error {
	m.stateMutex.Lock()
	defer m.stateMutex.Unlock()

	esp, exists := m.deviceStates[id]
	if !exists {
		return errors.New("ESP8266 device not found")
	}

	esp.ButtonState = pressed

	// Update metadata
	m.registry.UpdateDeviceMetadata(id, map[string]interface{}{
		"button_state": pressed,
	})

	return nil
}

// GetAllESP8266Devices returns all ESP8266 devices
func (m *ESP8266Manager) GetAllESP8266Devices() []*ESP8266Device {
	m.stateMutex.RLock()
	defer m.stateMutex.RUnlock()

	devices := make([]*ESP8266Device, 0, len(m.deviceStates))
	for _, device := range m.deviceStates {
		devices = append(devices, device)
	}

	return devices
}

// SendCommand sends a command to an ESP8266 device
// This would interface with the MQTT or other communication system
func (m *ESP8266Manager) SendCommand(id string, command string, params map[string]interface{}) error {
	// Check if device exists
	esp, err := m.GetESP8266(id)
	if err != nil {
		return err
	}

	// In a real implementation, this would send the command over MQTT or HTTP
	// For now, we just log it
	fmt.Printf("Sending command '%s' to device %s (%s) with params: %v\n",
		command, id, esp.Device.Name, params)

	return nil
}
