package mqtt

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"ranger/internal/core"
	"ranger/internal/device"
	"ranger/internal/util/logger"

	paho "github.com/eclipse/paho.mqtt.golang"
	"go.uber.org/zap"
)

// Client represents the MQTT client for the IoT blockchain toolkit
type Client struct {
	config     *Config
	client     paho.Client
	app        *core.App
	isRunning  bool
	mu         sync.RWMutex
	handlers   map[string]paho.MessageHandler
	log        *logger.Logger
	deviceSubs map[string]bool // Track subscribed device topics
}

// NewClient creates a new MQTT client
func NewClient(config *Config, app *core.App) *Client {
	client := &Client{
		config:     config,
		app:        app,
		isRunning:  false,
		handlers:   make(map[string]paho.MessageHandler),
		deviceSubs: make(map[string]bool),
		log:        logger.GetDefaultLogger().WithField("component", "mqtt"),
	}

	// Register default handlers
	client.registerDefaultHandlers()

	return client
}

// Start connects to the MQTT broker and starts the client
func (c *Client) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isRunning {
		return nil
	}

	c.log.Info("Starting MQTT client",
		zap.String("broker", c.config.Broker),
		zap.Int("port", c.config.Port))

	// Create MQTT client options
	opts := paho.NewClientOptions()
	brokerURL := fmt.Sprintf("tcp://%s:%d", c.config.Broker, c.config.Port)
	opts.AddBroker(brokerURL)
	opts.SetClientID(c.config.ClientID)

	if c.config.Username != "" {
		opts.SetUsername(c.config.Username)
		opts.SetPassword(c.config.Password)
	}

	// Set callbacks
	opts.SetOnConnectHandler(c.onConnect)
	opts.SetConnectionLostHandler(c.onConnectionLost)
	opts.SetAutoReconnect(true)
	opts.SetMaxReconnectInterval(1 * time.Minute)
	opts.SetCleanSession(true)
	opts.SetKeepAlive(30 * time.Second)

	// Create and connect the client
	c.client = paho.NewClient(opts)
	token := c.client.Connect()
	if token.Wait() && token.Error() != nil {
		return fmt.Errorf("failed to connect to MQTT broker: %w", token.Error())
	}

	c.isRunning = true
	c.log.Info("MQTT client started successfully")

	// Subscribe to global topics
	c.subscribeToGlobalTopics()

	// Subscribe to existing device topics
	c.subscribeToAllDevices()

	return nil
}

// Stop disconnects from the MQTT broker and stops the client
func (c *Client) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isRunning {
		return nil
	}

	c.log.Info("Stopping MQTT client")

	// Publish offline status before disconnecting
	c.PublishSystemStatus("offline")

	// Disconnect with a timeout
	c.client.Disconnect(1000)
	c.isRunning = false

	c.log.Info("MQTT client stopped")
	return nil
}

// IsRunning returns whether the client is running
func (c *Client) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.isRunning
}

// Publish publishes a message to the specified topic
func (c *Client) Publish(topic string, payload interface{}, retained bool) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.isRunning {
		return fmt.Errorf("mqtt client is not running")
	}

	// Convert payload to JSON string
	var payloadBytes []byte
	var err error

	switch p := payload.(type) {
	case string:
		payloadBytes = []byte(p)
	case []byte:
		payloadBytes = p
	default:
		payloadBytes, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal payload: %w", err)
		}
	}

	// Publish message
	token := c.client.Publish(topic, byte(c.config.QoS), retained, payloadBytes)
	if token.Wait() && token.Error() != nil {
		return fmt.Errorf("failed to publish message: %w", token.Error())
	}

	c.log.Debug("Published message",
		zap.String("topic", topic),
		zap.Int("payload_size", len(payloadBytes)),
		zap.Bool("retained", retained))

	return nil
}

// Subscribe subscribes to the specified topic
func (c *Client) Subscribe(topic string, handler paho.MessageHandler) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isRunning {
		return fmt.Errorf("mqtt client is not running")
	}

	// Register handler
	c.handlers[topic] = handler

	// Subscribe to topic
	token := c.client.Subscribe(topic, byte(c.config.QoS), handler)
	if token.Wait() && token.Error() != nil {
		delete(c.handlers, topic)
		return fmt.Errorf("failed to subscribe to topic: %w", token.Error())
	}

	c.log.Info("Subscribed to topic", zap.String("topic", topic))
	return nil
}

// Unsubscribe unsubscribes from the specified topic
func (c *Client) Unsubscribe(topic string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isRunning {
		return fmt.Errorf("mqtt client is not running")
	}

	// Unsubscribe from topic
	token := c.client.Unsubscribe(topic)
	if token.Wait() && token.Error() != nil {
		return fmt.Errorf("failed to unsubscribe from topic: %w", token.Error())
	}

	// Remove handler
	delete(c.handlers, topic)

	c.log.Info("Unsubscribed from topic", zap.String("topic", topic))
	return nil
}

// PublishDeviceCommand publishes a command to a device
func (c *Client) PublishDeviceCommand(deviceID, command string, params map[string]interface{}) error {
	topic := fmt.Sprintf("%s/device/%s/command", c.config.TopicRoot, deviceID)

	payload := map[string]interface{}{
		"command": command,
		"params":  params,
		"id":      fmt.Sprintf("cmd-%d", time.Now().UnixNano()),
		"time":    time.Now(),
	}

	return c.Publish(topic, payload, false)
}

// PublishSystemStatus publishes the system status
func (c *Client) PublishSystemStatus(status string) error {
	topic := fmt.Sprintf("%s/system/status", c.config.TopicRoot)

	payload := map[string]interface{}{
		"status": status,
		"time":   time.Now(),
	}

	return c.Publish(topic, payload, true)
}

// SubscribeToDevice subscribes to all topics for a device
func (c *Client) SubscribeToDevice(deviceID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isRunning {
		return fmt.Errorf("mqtt client is not running")
	}

	// Check if already subscribed
	if _, ok := c.deviceSubs[deviceID]; ok {
		return nil
	}

	// Subscribe to device status
	statusTopic := fmt.Sprintf("%s/device/%s/status", c.config.TopicRoot, deviceID)
	token := c.client.Subscribe(statusTopic, byte(c.config.QoS), c.handleDeviceStatus)
	if token.Wait() && token.Error() != nil {
		return fmt.Errorf("failed to subscribe to device status: %w", token.Error())
	}

	// Subscribe to device data
	dataTopic := fmt.Sprintf("%s/device/%s/data/#", c.config.TopicRoot, deviceID)
	token = c.client.Subscribe(dataTopic, byte(c.config.QoS), c.handleDeviceData)
	if token.Wait() && token.Error() != nil {
		return fmt.Errorf("failed to subscribe to device data: %w", token.Error())
	}

	c.deviceSubs[deviceID] = true
	c.log.Info("Subscribed to device topics", zap.String("device_id", deviceID))

	return nil
}

// UnsubscribeFromDevice unsubscribes from all topics for a device
func (c *Client) UnsubscribeFromDevice(deviceID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isRunning {
		return fmt.Errorf("mqtt client is not running")
	}

	// Check if subscribed
	if _, ok := c.deviceSubs[deviceID]; !ok {
		return nil
	}

	// Unsubscribe from device status
	statusTopic := fmt.Sprintf("%s/device/%s/status", c.config.TopicRoot, deviceID)
	token := c.client.Unsubscribe(statusTopic)
	if token.Wait() && token.Error() != nil {
		return fmt.Errorf("failed to unsubscribe from device status: %w", token.Error())
	}

	// Unsubscribe from device data
	dataTopic := fmt.Sprintf("%s/device/%s/data/#", c.config.TopicRoot, deviceID)
	token = c.client.Unsubscribe(dataTopic)
	if token.Wait() && token.Error() != nil {
		return fmt.Errorf("failed to unsubscribe from device data: %w", token.Error())
	}

	delete(c.deviceSubs, deviceID)
	c.log.Info("Unsubscribed from device topics", zap.String("device_id", deviceID))

	return nil
}

// Event handlers

// onConnect is called when the client connects to the broker
func (c *Client) onConnect(client paho.Client) {
	c.log.Info("Connected to MQTT broker")

	// Publish online status
	c.PublishSystemStatus("online")

	// Resubscribe to all topics
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Resubscribe to global topics
	c.subscribeToGlobalTopics()

	// Resubscribe to device topics
	for deviceID := range c.deviceSubs {
		statusTopic := fmt.Sprintf("%s/device/%s/status", c.config.TopicRoot, deviceID)
		dataTopic := fmt.Sprintf("%s/device/%s/data/#", c.config.TopicRoot, deviceID)

		client.Subscribe(statusTopic, byte(c.config.QoS), c.handleDeviceStatus)
		client.Subscribe(dataTopic, byte(c.config.QoS), c.handleDeviceData)
	}
}

// onConnectionLost is called when the connection to the broker is lost
func (c *Client) onConnectionLost(client paho.Client, err error) {
	c.log.Error("Lost connection to MQTT broker", zap.Error(err))
}

// subscribeToGlobalTopics subscribes to global system topics
func (c *Client) subscribeToGlobalTopics() {
	if !c.isRunning {
		return
	}

	// Subscribe to system commands
	systemTopic := fmt.Sprintf("%s/system/command", c.config.TopicRoot)
	c.client.Subscribe(systemTopic, byte(c.config.QoS), c.handleSystemCommand)

	// Subscribe to device registry updates
	registryTopic := fmt.Sprintf("%s/registry/#", c.config.TopicRoot)
	c.client.Subscribe(registryTopic, byte(c.config.QoS), c.handleRegistryUpdate)
}

// subscribeToAllDevices subscribes to topics for all registered devices
func (c *Client) subscribeToAllDevices() {
	devices := c.app.DeviceRegistry.ListDevices()
	for _, dev := range devices {
		c.SubscribeToDevice(dev.ID)
	}
}

// Message handlers

// registerDefaultHandlers sets up the default message handlers
func (c *Client) registerDefaultHandlers() {
	// Will be implemented in handlers.go
}

// handleDeviceStatus processes device status updates
func (c *Client) handleDeviceStatus(client paho.Client, msg paho.Message) {
	// Extract device ID from topic
	topic := msg.Topic()
	deviceID := extractDeviceIDFromTopic(topic)
	if deviceID == "" {
		c.log.Warn("Could not extract device ID from topic", zap.String("topic", topic))
		return
	}

	status := string(msg.Payload())
	c.log.Info("Received device status update",
		zap.String("device_id", deviceID),
		zap.String("status", status))

	// Update device status in registry
	var deviceStatus device.DeviceStatus
	switch status {
	case "online":
		deviceStatus = device.Online
	case "offline":
		deviceStatus = device.Offline
	default:
		deviceStatus = device.Unknown
	}

	err := c.app.DeviceRegistry.UpdateDeviceStatus(deviceID, deviceStatus)
	if err != nil {
		c.log.Error("Failed to update device status",
			zap.String("device_id", deviceID),
			zap.Error(err))
	}
}

// handleDeviceData processes device data messages
func (c *Client) handleDeviceData(client paho.Client, msg paho.Message) {
	// Extract device ID from topic
	topic := msg.Topic()
	deviceID := extractDeviceIDFromTopic(topic)
	if deviceID == "" {
		c.log.Warn("Could not extract device ID from topic", zap.String("topic", topic))
		return
	}

	// Extract sensor type from topic
	sensorType := extractSensorTypeFromTopic(topic)
	if sensorType == "" {
		c.log.Warn("Could not extract sensor type from topic", zap.String("topic", topic))
		return
	}

	c.log.Info("Received device data",
		zap.String("device_id", deviceID),
		zap.String("sensor", sensorType))

	// Parse data
	var value float64
	err := json.Unmarshal(msg.Payload(), &value)
	if err != nil {
		// Try parsing as an object with a value field
		var dataObj struct {
			Value float64 `json:"value"`
		}
		err = json.Unmarshal(msg.Payload(), &dataObj)
		if err != nil {
			c.log.Error("Failed to parse device data",
				zap.String("device_id", deviceID),
				zap.Error(err))
			return
		}
		value = dataObj.Value
	}

	// Update last seen timestamp
	c.app.DeviceRegistry.UpdateLastSeen(deviceID)

	// Process sensor data
	switch sensorType {
	case "temperature", "humidity", "pressure", "light", "motion":
		// Handle sensor reading
		if err := c.app.ESP8266Manager.UpdateSensorReading(deviceID, sensorType, value); err != nil {
			c.log.Error("Failed to update sensor reading",
				zap.String("device_id", deviceID),
				zap.String("sensor", sensorType),
				zap.Error(err))
			return
		}
	case "led":
		// Handle LED state
		if err := c.app.ESP8266Manager.SetLEDState(deviceID, value > 0.5); err != nil {
			c.log.Error("Failed to update LED state",
				zap.String("device_id", deviceID),
				zap.Error(err))
			return
		}
	case "button":
		// Handle button state
		if err := c.app.ESP8266Manager.UpdateButtonState(deviceID, value > 0.5); err != nil {
			c.log.Error("Failed to update button state",
				zap.String("device_id", deviceID),
				zap.Error(err))
			return
		}
	default:
		// Handle generic data
		c.log.Info("Received generic sensor data",
			zap.String("device_id", deviceID),
			zap.String("sensor", sensorType),
			zap.Float64("value", value))
	}

	// Record data to blockchain
	data := map[string]interface{}{
		"sensor":    sensorType,
		"value":     value,
		"timestamp": time.Now(),
	}

	dataBytes, _ := json.Marshal(data)
	if err := c.app.ProcessDeviceData(deviceID, dataBytes); err != nil {
		c.log.Error("Failed to record data to blockchain",
			zap.String("device_id", deviceID),
			zap.Error(err))
	}
}

// handleSystemCommand processes system command messages
func (c *Client) handleSystemCommand(client paho.Client, msg paho.Message) {
	// Parse command
	var command struct {
		Action string      `json:"action"`
		Params interface{} `json:"params"`
	}

	if err := json.Unmarshal(msg.Payload(), &command); err != nil {
		c.log.Error("Failed to parse system command", zap.Error(err))
		return
	}

	c.log.Info("Received system command", zap.String("action", command.Action))

	// Process command
	switch command.Action {
	case "mine":
		// Mine a new block
		_, err := c.app.Blockchain.MineBlock("MQTT_COMMAND")
		if err != nil {
			c.log.Error("Failed to mine block", zap.Error(err))
		} else {
			c.log.Info("Mined new block via MQTT command")
		}
	case "validate":
		// Validate blockchain
		isValid := c.app.Blockchain.ValidateChain()
		c.log.Info("Blockchain validation result", zap.Bool("is_valid", isValid))
	case "restart":
		// Restart application (not implemented)
		c.log.Warn("Restart command not implemented")
	default:
		c.log.Warn("Unknown system command", zap.String("action", command.Action))
	}
}

// handleRegistryUpdate processes device registry update messages
func (c *Client) handleRegistryUpdate(client paho.Client, msg paho.Message) {
	// For future implementation
	c.log.Debug("Registry update received (not implemented)", zap.String("topic", msg.Topic()))
}

// Helper functions

// extractDeviceIDFromTopic extracts the device ID from a topic string
func extractDeviceIDFromTopic(topic string) string {
	// Topic format: root/device/{deviceID}/...
	parts := splitTopic(topic)
	if len(parts) >= 3 && parts[0] != "" && parts[1] == "device" {
		return parts[2]
	}
	return ""
}

// extractSensorTypeFromTopic extracts the sensor type from a topic string
func extractSensorTypeFromTopic(topic string) string {
	// Topic format: root/device/{deviceID}/data/{sensorType}
	parts := splitTopic(topic)
	if len(parts) >= 5 && parts[0] != "" && parts[1] == "device" && parts[3] == "data" {
		return parts[4]
	}
	return ""
}

// splitTopic splits a topic into parts
func splitTopic(topic string) []string {
	// Split by slash
	parts := strings.Split(topic, "/")

	// Skip processing if too short
	if len(parts) < 2 {
		return parts
	}

	// Check if the first part is empty (usually means absolute topic path)
	if parts[0] == "" {
		// Remove the empty first part
		return parts[1:]
	}

	return parts
}
