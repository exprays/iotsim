package mqtt

import (
	"encoding/json"
	"fmt"
	"time"

	"ranger/internal/device"

	paho "github.com/eclipse/paho.mqtt.golang"
	"go.uber.org/zap"
)

// Message types
type DeviceMessage struct {
	DeviceID  string      `json:"device_id"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
}

type DeviceCommand struct {
	Command string                 `json:"command"`
	Params  map[string]interface{} `json:"params"`
	ID      string                 `json:"id"`
	Time    time.Time              `json:"time"`
}

type DeviceResponse struct {
	CommandID string      `json:"command_id"`
	Success   bool        `json:"success"`
	Message   string      `json:"message,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	Time      time.Time   `json:"time"`
}

type DeviceStatus struct {
	Status          string    `json:"status"`
	Time            time.Time `json:"time"`
	Address         string    `json:"address,omitempty"`
	FirmwareVersion string    `json:"firmware_version,omitempty"`
}

type SystemCommand struct {
	Action string      `json:"action"`
	Params interface{} `json:"params"`
	ID     string      `json:"id"`
	Time   time.Time   `json:"time"`
}

// handleDiscovery processes device discovery messages
func (c *Client) handleDiscovery(client paho.Client, msg paho.Message) {
	c.log.Info("Received device discovery request")

	// Parse discovery request
	var discoveryReq struct {
		DeviceType string                 `json:"device_type"`
		DeviceName string                 `json:"device_name"`
		Metadata   map[string]interface{} `json:"metadata"`
		Address    string                 `json:"address"`
	}

	if err := json.Unmarshal(msg.Payload(), &discoveryReq); err != nil {
		c.log.Error("Failed to parse discovery request", zap.Error(err))
		return
	}

	// Map device type
	deviceType := device.Generic
	switch discoveryReq.DeviceType {
	case "esp8266":
		deviceType = device.ESP8266
	case "generic":
		deviceType = device.Generic
	}

	// Default capabilities based on device type
	capabilities := []string{"data_storage", "blockchain_integration"}
	if deviceType == device.ESP8266 {
		capabilities = append(capabilities, "led_control", "sensor_readings")
	}

	// Register device
	dev, err := c.app.RegisterDevice(
		discoveryReq.DeviceName,
		deviceType,
		capabilities,
		discoveryReq.Metadata,
	)

	if err != nil {
		c.log.Error("Failed to register device from discovery", zap.Error(err))
		return
	}

	// Subscribe to this device's topics
	c.SubscribeToDevice(dev.ID)

	// Send registration confirmation
	responseTopic := "iot-blockchain/discovery/response"
	responsePayload := map[string]interface{}{
		"device_id":     dev.ID,
		"api_key":       dev.APIKey,
		"registered":    true,
		"timestamp":     time.Now(),
		"status_topic":  fmt.Sprintf("%s/device/%s/status", c.config.TopicRoot, dev.ID),
		"command_topic": fmt.Sprintf("%s/device/%s/command", c.config.TopicRoot, dev.ID),
	}

	if err := c.Publish(responseTopic, responsePayload, false); err != nil {
		c.log.Error("Failed to publish discovery response", zap.Error(err))
	}

	c.log.Info("Device registered via discovery",
		zap.String("device_id", dev.ID),
		zap.String("name", dev.Name),
		zap.String("type", string(dev.Type)))
}

// handleDeviceResponse processes device command responses
func (c *Client) handleDeviceResponse(client paho.Client, msg paho.Message) {
	// Extract device ID from topic
	topic := msg.Topic()
	deviceID := extractDeviceIDFromTopic(topic)
	if deviceID == "" {
		c.log.Warn("Could not extract device ID from topic", zap.String("topic", topic))
		return
	}

	// Parse response
	var response DeviceResponse
	if err := json.Unmarshal(msg.Payload(), &response); err != nil {
		c.log.Error("Failed to parse device response",
			zap.String("device_id", deviceID),
			zap.Error(err))
		return
	}

	c.log.Info("Received device command response",
		zap.String("device_id", deviceID),
		zap.String("command_id", response.CommandID),
		zap.Bool("success", response.Success))

	// Update device last seen
	c.app.DeviceRegistry.UpdateLastSeen(deviceID)

	// Publish event
	eventTopic := fmt.Sprintf("%s/events/device_command_response", c.config.TopicRoot)
	c.Publish(eventTopic, map[string]interface{}{
		"device_id":  deviceID,
		"command_id": response.CommandID,
		"success":    response.Success,
		"message":    response.Message,
		"data":       response.Data,
	}, false)
}

// handleDeviceSystem processes device system metrics
func (c *Client) handleDeviceSystem(client paho.Client, msg paho.Message) {
	// Extract device ID and metric from topic
	topic := msg.Topic()
	deviceID := extractDeviceIDFromTopic(topic)
	if deviceID == "" {
		c.log.Warn("Could not extract device ID from topic", zap.String("topic", topic))
		return
	}

	// Extract the metric type
	parts := splitTopic(topic)
	if len(parts) < 5 || parts[3] != "system" {
		c.log.Warn("Invalid system metric topic", zap.String("topic", topic))
		return
	}
	metricType := parts[4]

	// Parse the metric value
	var value float64
	if err := json.Unmarshal(msg.Payload(), &value); err != nil {
		// Try parsing as an object with a value field
		var metricObj struct {
			Value float64 `json:"value"`
		}
		if err := json.Unmarshal(msg.Payload(), &metricObj); err != nil {
			c.log.Error("Failed to parse system metric",
				zap.String("device_id", deviceID),
				zap.String("metric", metricType),
				zap.Error(err))
			return
		}
		value = metricObj.Value
	}

	c.log.Info("Received device system metric",
		zap.String("device_id", deviceID),
		zap.String("metric", metricType),
		zap.Float64("value", value))

	// Update device last seen
	c.app.DeviceRegistry.UpdateLastSeen(deviceID)

	// Update device metadata with system metric
	device, err := c.app.DeviceRegistry.GetDeviceByID(deviceID)
	if err != nil {
		c.log.Error("Failed to get device for system metric update",
			zap.String("device_id", deviceID),
			zap.Error(err))
		return
	}

	// Initialize metadata if it doesn't exist
	if device.Metadata == nil {
		device.Metadata = make(map[string]interface{})
	}

	// Create or update system metrics section
	var metrics map[string]interface{}
	if m, ok := device.Metadata["system_metrics"].(map[string]interface{}); ok {
		metrics = m
	} else {
		metrics = make(map[string]interface{})
	}

	// Update the specific metric
	metrics[metricType] = value
	device.Metadata["system_metrics"] = metrics

	// Save the updated metadata
	err = c.app.DeviceRegistry.UpdateDeviceMetadata(deviceID, device.Metadata)
	if err != nil {
		c.log.Error("Failed to update device metadata with system metric",
			zap.String("device_id", deviceID),
			zap.Error(err))
	}
}
