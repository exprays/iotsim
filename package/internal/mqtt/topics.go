package mqtt

import (
	"fmt"
	"strings"
)

// Topic prefixes
const (
	DeviceTopic     = "device"
	SystemTopic     = "system"
	RegistryTopic   = "registry"
	BlockchainTopic = "blockchain"
	DiscoveryTopic  = "discovery"
)

// Topic suffixes
const (
	StatusSuffix   = "status"
	CommandSuffix  = "command"
	ResponseSuffix = "response"
	DataSuffix     = "data"
	EventSuffix    = "event"
	SystemSuffix   = "system"
	ConfigSuffix   = "config"
	LedSuffix      = "led"
	ButtonSuffix   = "button"
)

// Device status values
const (
	StatusOnline   = "online"
	StatusOffline  = "offline"
	StatusSleeping = "sleeping"
	StatusError    = "error"
)

// GetDeviceStatusTopic returns the topic for device status
func GetDeviceStatusTopic(root, deviceID string) string {
	return fmt.Sprintf("%s/%s/%s/%s", root, DeviceTopic, deviceID, StatusSuffix)
}

// GetDeviceCommandTopic returns the topic for device commands
func GetDeviceCommandTopic(root, deviceID string) string {
	return fmt.Sprintf("%s/%s/%s/%s", root, DeviceTopic, deviceID, CommandSuffix)
}

// GetDeviceResponseTopic returns the topic for device command responses
func GetDeviceResponseTopic(root, deviceID string) string {
	return fmt.Sprintf("%s/%s/%s/%s", root, DeviceTopic, deviceID, ResponseSuffix)
}

// GetDeviceDataTopic returns the topic for device data
func GetDeviceDataTopic(root, deviceID, sensorType string) string {
	return fmt.Sprintf("%s/%s/%s/%s/%s", root, DeviceTopic, deviceID, DataSuffix, sensorType)
}

// GetDeviceLedTopic returns the topic for device LED status/control
func GetDeviceLedTopic(root, deviceID string) string {
	return fmt.Sprintf("%s/%s/%s/%s", root, DeviceTopic, deviceID, LedSuffix)
}

// GetDeviceButtonTopic returns the topic for device button events
func GetDeviceButtonTopic(root, deviceID string) string {
	return fmt.Sprintf("%s/%s/%s/%s", root, DeviceTopic, deviceID, ButtonSuffix)
}

// GetDeviceSystemTopic returns the topic for device system metrics
func GetDeviceSystemTopic(root, deviceID, metricType string) string {
	return fmt.Sprintf("%s/%s/%s/%s/%s", root, DeviceTopic, deviceID, SystemSuffix, metricType)
}

// GetDeviceConfigTopic returns the topic for device configuration
func GetDeviceConfigTopic(root, deviceID string) string {
	return fmt.Sprintf("%s/%s/%s/%s", root, DeviceTopic, deviceID, ConfigSuffix)
}

// GetSystemStatusTopic returns the topic for system status
func GetSystemStatusTopic(root string) string {
	return fmt.Sprintf("%s/%s/%s", root, SystemTopic, StatusSuffix)
}

// GetSystemCommandTopic returns the topic for system commands
func GetSystemCommandTopic(root string) string {
	return fmt.Sprintf("%s/%s/%s", root, SystemTopic, CommandSuffix)
}

// GetSystemEventTopic returns the topic for system events
func GetSystemEventTopic(root, eventType string) string {
	return fmt.Sprintf("%s/%s/%s/%s", root, SystemTopic, EventSuffix, eventType)
}

// GetRegistryUpdateTopic returns the topic for registry updates
func GetRegistryUpdateTopic(root string) string {
	return fmt.Sprintf("%s/%s/update", root, RegistryTopic)
}

// GetBlockchainEventTopic returns the topic for blockchain events
func GetBlockchainEventTopic(root, eventType string) string {
	return fmt.Sprintf("%s/%s/%s/%s", root, BlockchainTopic, EventSuffix, eventType)
}

// GetDiscoveryTopic returns the topic for device discovery
func GetDiscoveryTopic(root string) string {
	return fmt.Sprintf("%s/%s", root, DiscoveryTopic)
}

// IsDeviceStatusTopic checks if a topic is a device status topic
func IsDeviceStatusTopic(topic, root string) bool {
	parts := strings.Split(topic, "/")
	return len(parts) >= 4 && parts[0] == root && parts[1] == DeviceTopic && parts[3] == StatusSuffix
}

// IsDeviceCommandTopic checks if a topic is a device command topic
func IsDeviceCommandTopic(topic, root string) bool {
	parts := strings.Split(topic, "/")
	return len(parts) >= 4 && parts[0] == root && parts[1] == DeviceTopic && parts[3] == CommandSuffix
}

// IsDeviceResponseTopic checks if a topic is a device response topic
func IsDeviceResponseTopic(topic, root string) bool {
	parts := strings.Split(topic, "/")
	return len(parts) >= 4 && parts[0] == root && parts[1] == DeviceTopic && parts[3] == ResponseSuffix
}

// IsDeviceDataTopic checks if a topic is a device data topic
func IsDeviceDataTopic(topic, root string) bool {
	parts := strings.Split(topic, "/")
	return len(parts) >= 5 && parts[0] == root && parts[1] == DeviceTopic && parts[3] == DataSuffix
}

// IsDeviceLedTopic checks if a topic is a device LED topic
func IsDeviceLedTopic(topic, root string) bool {
	parts := strings.Split(topic, "/")
	return len(parts) >= 4 && parts[0] == root && parts[1] == DeviceTopic && parts[3] == LedSuffix
}

// IsDeviceButtonTopic checks if a topic is a device button topic
func IsDeviceButtonTopic(topic, root string) bool {
	parts := strings.Split(topic, "/")
	return len(parts) >= 4 && parts[0] == root && parts[1] == DeviceTopic && parts[3] == ButtonSuffix
}

// IsDeviceSystemTopic checks if a topic is a device system topic
func IsDeviceSystemTopic(topic, root string) bool {
	parts := strings.Split(topic, "/")
	return len(parts) >= 5 && parts[0] == root && parts[1] == DeviceTopic && parts[3] == SystemSuffix
}

// IsDeviceConfigTopic checks if a topic is a device config topic
func IsDeviceConfigTopic(topic, root string) bool {
	parts := strings.Split(topic, "/")
	return len(parts) >= 4 && parts[0] == root && parts[1] == DeviceTopic && parts[3] == ConfigSuffix
}

// IsSystemStatusTopic checks if a topic is a system status topic
func IsSystemStatusTopic(topic, root string) bool {
	parts := strings.Split(topic, "/")
	return len(parts) >= 3 && parts[0] == root && parts[1] == SystemTopic && parts[2] == StatusSuffix
}

// IsSystemCommandTopic checks if a topic is a system command topic
func IsSystemCommandTopic(topic, root string) bool {
	parts := strings.Split(topic, "/")
	return len(parts) >= 3 && parts[0] == root && parts[1] == SystemTopic && parts[2] == CommandSuffix
}

// IsSystemEventTopic checks if a topic is a system event topic
func IsSystemEventTopic(topic, root string) bool {
	parts := strings.Split(topic, "/")
	return len(parts) >= 4 && parts[0] == root && parts[1] == SystemTopic && parts[2] == EventSuffix
}

// IsRegistryUpdateTopic checks if a topic is a registry update topic
func IsRegistryUpdateTopic(topic, root string) bool {
	parts := strings.Split(topic, "/")
	return len(parts) >= 3 && parts[0] == root && parts[1] == RegistryTopic && parts[2] == "update"
}

// IsBlockchainEventTopic checks if a topic is a blockchain event topic
func IsBlockchainEventTopic(topic, root string) bool {
	parts := strings.Split(topic, "/")
	return len(parts) >= 4 && parts[0] == root && parts[1] == BlockchainTopic && parts[2] == EventSuffix
}

// IsDiscoveryTopic checks if a topic is the discovery topic
func IsDiscoveryTopic(topic, root string) bool {
	parts := strings.Split(topic, "/")
	return len(parts) >= 2 && parts[0] == root && parts[1] == DiscoveryTopic
}

// ExtractDeviceID extracts the device ID from a device topic
func ExtractDeviceID(topic, root string) (string, error) {
	parts := strings.Split(topic, "/")
	if len(parts) < 3 || parts[0] != root || parts[1] != DeviceTopic {
		return "", fmt.Errorf("invalid device topic format: %s", topic)
	}
	return parts[2], nil
}

// ExtractSensorType extracts the sensor type from a device data topic
func ExtractSensorType(topic, root string) (string, error) {
	parts := strings.Split(topic, "/")
	if len(parts) < 5 || parts[0] != root || parts[1] != DeviceTopic || parts[3] != DataSuffix {
		return "", fmt.Errorf("invalid device data topic format: %s", topic)
	}
	return parts[4], nil
}

// ExtractSystemMetricType extracts the metric type from a device system topic
func ExtractSystemMetricType(topic, root string) (string, error) {
	parts := strings.Split(topic, "/")
	if len(parts) < 5 || parts[0] != root || parts[1] != DeviceTopic || parts[3] != SystemSuffix {
		return "", fmt.Errorf("invalid device system topic format: %s", topic)
	}
	return parts[4], nil
}

// ExtractEventType extracts the event type from a system event topic
func ExtractEventType(topic, root string) (string, error) {
	parts := strings.Split(topic, "/")
	if len(parts) < 4 || parts[0] != root || parts[1] != SystemTopic || parts[2] != EventSuffix {
		return "", fmt.Errorf("invalid system event topic format: %s", topic)
	}
	return parts[3], nil
}

// ExtractBlockchainEventType extracts the event type from a blockchain event topic
func ExtractBlockchainEventType(topic, root string) (string, error) {
	parts := strings.Split(topic, "/")
	if len(parts) < 4 || parts[0] != root || parts[1] != BlockchainTopic || parts[2] != EventSuffix {
		return "", fmt.Errorf("invalid blockchain event topic format: %s", topic)
	}
	return parts[3], nil
}
