package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"ranger/internal/blockchain"
	"ranger/internal/device"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
)

// Response formats

// APIResponse is the standard API response format
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// SystemStatusResponse contains system status information
type SystemStatusResponse struct {
	Status           string        `json:"status"`
	Uptime           time.Duration `json:"uptime"`
	APIVersion       string        `json:"apiVersion"`
	BlockchainStatus struct {
		BlockCount          int    `json:"blockCount"`
		PendingTransactions int    `json:"pendingTransactions"`
		IsValid             bool   `json:"isValid"`
		LastBlockHash       string `json:"lastBlockHash"`
	} `json:"blockchainStatus"`
	DeviceStatus struct {
		TotalDevices  int `json:"totalDevices"`
		OnlineDevices int `json:"onlineDevices"`
	} `json:"deviceStatus"`
}

// BlockchainStatusResponse contains blockchain status information
type BlockchainStatusResponse struct {
	BlockCount          int    `json:"blockCount"`
	PendingTransactions int    `json:"pendingTransactions"`
	IsValid             bool   `json:"isValid"`
	LastBlockHash       string `json:"lastBlockHash"`
	Difficulty          uint8  `json:"difficulty"`
}

// DeviceResponse represents a device in API responses
type DeviceResponse struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Type            string                 `json:"type"`
	Status          string                 `json:"status"`
	LastSeen        time.Time              `json:"lastSeen"`
	RegisteredAt    time.Time              `json:"registeredAt"`
	BlockchainAddr  string                 `json:"blockchainAddr"`
	Capabilities    []string               `json:"capabilities"`
	Metadata        map[string]interface{} `json:"metadata"`
	FirmwareVersion string                 `json:"firmwareVersion,omitempty"`
}

// RegisterDeviceRequest is the request format for registering a device
type RegisterDeviceRequest struct {
	Name         string                 `json:"name"`
	Type         string                 `json:"type"`
	Capabilities []string               `json:"capabilities"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// RegisterESP8266Request is the request format for registering an ESP8266
type RegisterESP8266Request struct {
	Name     string `json:"name"`
	WifiSSID string `json:"wifiSsid"`
}

// UpdateDeviceStatusRequest is the request format for updating device status
type UpdateDeviceStatusRequest struct {
	Status string `json:"status"`
}

// SendCommandRequest is the request format for sending a command to a device
type SendCommandRequest struct {
	Command string                 `json:"command"`
	Params  map[string]interface{} `json:"params"`
}

// LoginRequest is the request format for authentication
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse is the response format for successful authentication
type LoginResponse struct {
	Token        string `json:"token"`
	ExpiresAt    int64  `json:"expiresAt"`
	RefreshToken string `json:"refreshToken"`
}

// UpdateLEDRequest is the request format for updating LED state
type UpdateLEDRequest struct {
	State bool `json:"state"`
}

// Handler methods

// HealthCheckHandler handles requests to the health check endpoint
func (r *Router) HealthCheckHandler(w http.ResponseWriter, req *http.Request) {
	response := map[string]string{
		"status":    "ok",
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   "1.0.0",
	}
	respondWithJSON(w, http.StatusOK, response)
}

// LoginHandler authenticates users and issues JWT tokens
func (r *Router) LoginHandler(w http.ResponseWriter, req *http.Request) {
	var loginReq LoginRequest
	if err := json.NewDecoder(req.Body).Decode(&loginReq); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request format")
		return
	}

	// In a real implementation, you would validate credentials against a database
	// This is a simplified version for demonstration
	if loginReq.Username == "admin" && loginReq.Password == "password" {
		// Create token
		expirationTime := time.Now().Add(24 * time.Hour)
		claims := &Claims{
			UserID:   "1",
			Username: loginReq.Username,
			Roles:    []string{"admin"},
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(expirationTime),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				Issuer:    "iot-blockchain-toolkit",
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(r.config.JWTSecret))
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Error creating token")
			return
		}

		// Create refresh token (simplified)
		refreshToken := fmt.Sprintf("refresh-%d", time.Now().UnixNano())

		response := LoginResponse{
			Token:        tokenString,
			ExpiresAt:    expirationTime.Unix(),
			RefreshToken: refreshToken,
		}
		respondWithJSON(w, http.StatusOK, response)
		return
	}

	respondWithError(w, http.StatusUnauthorized, "Invalid credentials")
}

// SystemStatusHandler returns overall system status
func (r *Router) SystemStatusHandler(w http.ResponseWriter, req *http.Request) {
	status := SystemStatusResponse{
		Status:     r.app.GetStatus(),
		Uptime:     r.app.GetUptime(),
		APIVersion: "v1",
	}

	// Add blockchain status
	chainLength := r.app.Blockchain.GetChainLength()
	status.BlockchainStatus.BlockCount = chainLength
	status.BlockchainStatus.PendingTransactions = r.app.Blockchain.GetPendingTransactionsCount()
	status.BlockchainStatus.IsValid = r.app.Blockchain.ValidateChain()

	if chainLength > 0 {
		lastBlock := r.app.Blockchain.Chain[chainLength-1]
		status.BlockchainStatus.LastBlockHash = lastBlock.Hash
	}

	// Add device status
	devices := r.app.DeviceRegistry.ListDevices()
	status.DeviceStatus.TotalDevices = len(devices)

	onlineCount := 0
	for _, dev := range devices {
		if dev.Status == device.Online {
			onlineCount++
		}
	}
	status.DeviceStatus.OnlineDevices = onlineCount

	respondWithJSON(w, http.StatusOK, status)
}

// SystemMetricsHandler returns system metrics
func (r *Router) SystemMetricsHandler(w http.ResponseWriter, req *http.Request) {
	// In a real implementation, you would collect various system metrics
	metrics := map[string]interface{}{
		"blockchainSize": r.app.Blockchain.GetChainLength(),
		"deviceCount":    r.app.DeviceRegistry.GetDeviceCount(),
		"uptime":         r.app.GetUptime().Seconds(),
	}

	respondWithJSON(w, http.StatusOK, metrics)
}

// BlockchainStatusHandler returns blockchain status
func (r *Router) BlockchainStatusHandler(w http.ResponseWriter, req *http.Request) {
	chainLength := r.app.Blockchain.GetChainLength()

	status := BlockchainStatusResponse{
		BlockCount:          chainLength,
		PendingTransactions: r.app.Blockchain.GetPendingTransactionsCount(),
		IsValid:             r.app.Blockchain.ValidateChain(),
		Difficulty:          r.app.Blockchain.Difficulty,
	}

	if chainLength > 0 {
		lastBlock := r.app.Blockchain.Chain[chainLength-1]
		status.LastBlockHash = lastBlock.Hash
	}

	respondWithJSON(w, http.StatusOK, status)
}

// GetBlocksHandler returns blocks from the blockchain
func (r *Router) GetBlocksHandler(w http.ResponseWriter, req *http.Request) {
	// Parse query parameters
	limit := 10
	offset := 0

	limitStr := req.URL.Query().Get("limit")
	if limitStr != "" {
		if val, err := strconv.Atoi(limitStr); err == nil && val > 0 {
			limit = val
		}
	}

	offsetStr := req.URL.Query().Get("offset")
	if offsetStr != "" {
		if val, err := strconv.Atoi(offsetStr); err == nil && val >= 0 {
			offset = val
		}
	}

	// Get blocks
	chainLength := r.app.Blockchain.GetChainLength()
	if offset >= chainLength {
		respondWithJSON(w, http.StatusOK, []interface{}{})
		return
	}

	// Calculate the actual slice indices
	start := chainLength - offset - 1
	end := start - limit + 1
	if end < 0 {
		end = 0
	}

	// Extract the blocks
	blocks := make([]blockchain.Block, 0, start-end+1)
	for i := start; i >= end; i-- {
		blocks = append(blocks, r.app.Blockchain.Chain[i])
	}

	respondWithJSON(w, http.StatusOK, blocks)
}

// GetBlockByHashHandler returns a specific block by hash
func (r *Router) GetBlockByHashHandler(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	hash := vars["hash"]

	block, err := r.app.Blockchain.GetBlockByHash(hash)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Block not found")
		return
	}

	respondWithJSON(w, http.StatusOK, block)
}

// GetTransactionsHandler returns recent transactions
func (r *Router) GetTransactionsHandler(w http.ResponseWriter, req *http.Request) {
	// In a real implementation, you would provide pagination and filtering
	// This is a simplified version

	// Collect all transactions from the blockchain
	txs := []blockchain.Transaction{}

	for _, block := range r.app.Blockchain.Chain {
		for _, tx := range block.Transactions {
			txs = append(txs, tx)
		}
	}

	// Add pending transactions
	for _, tx := range r.app.Blockchain.PendingTransactions {
		txs = append(txs, tx)
	}

	// Reverse the order to get newest first
	// This is inefficient but works for a demo
	reversed := []blockchain.Transaction{}
	for i := len(txs) - 1; i >= 0; i-- {
		reversed = append(reversed, txs[i])
	}

	// Limit to the most recent 100 transactions
	if len(reversed) > 100 {
		reversed = reversed[:100]
	}

	respondWithJSON(w, http.StatusOK, reversed)
}

// GetTransactionByIDHandler returns a specific transaction by ID
func (r *Router) GetTransactionByIDHandler(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id := vars["id"]

	// Look for the transaction in blocks
	for _, block := range r.app.Blockchain.Chain {
		for _, tx := range block.Transactions {
			if tx.ID == id {
				respondWithJSON(w, http.StatusOK, tx)
				return
			}
		}
	}

	// Look for the transaction in pending transactions
	for _, tx := range r.app.Blockchain.PendingTransactions {
		if tx.ID == id {
			respondWithJSON(w, http.StatusOK, tx)
			return
		}
	}

	respondWithError(w, http.StatusNotFound, "Transaction not found")
}

// MineBlockHandler manually triggers mining a new block
func (r *Router) MineBlockHandler(w http.ResponseWriter, req *http.Request) {
	if r.app.Blockchain.GetPendingTransactionsCount() == 0 {
		respondWithError(w, http.StatusBadRequest, "No pending transactions to mine")
		return
	}

	// Get miner address from query or use default
	minerAddress := req.URL.Query().Get("minerAddress")
	if minerAddress == "" {
		minerAddress = "SYSTEM"
	}

	block, err := r.app.Blockchain.MineBlock(minerAddress)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Mining failed: %v", err))
		return
	}

	respondWithJSON(w, http.StatusCreated, block)
}

// ValidateBlockchainHandler checks the integrity of the blockchain
func (r *Router) ValidateBlockchainHandler(w http.ResponseWriter, req *http.Request) {
	isValid := r.app.Blockchain.ValidateChain()

	response := map[string]interface{}{
		"valid":      isValid,
		"blockCount": r.app.Blockchain.GetChainLength(),
	}

	respondWithJSON(w, http.StatusOK, response)
}

// ListDevicesHandler returns all registered devices
func (r *Router) ListDevicesHandler(w http.ResponseWriter, req *http.Request) {
	devices := r.app.DeviceRegistry.ListDevices()

	// Convert to API response format
	response := make([]DeviceResponse, len(devices))
	for i, d := range devices {
		response[i] = DeviceResponse{
			ID:              d.ID,
			Name:            d.Name,
			Type:            string(d.Type),
			Status:          string(d.Status),
			LastSeen:        d.LastSeen,
			RegisteredAt:    d.RegisteredAt,
			BlockchainAddr:  d.BlockchainAddr,
			Capabilities:    d.Capabilities,
			Metadata:        d.Metadata,
			FirmwareVersion: d.FirmwareVersion,
		}
	}

	respondWithJSON(w, http.StatusOK, response)
}

// RegisterDeviceHandler registers a new device
func (r *Router) RegisterDeviceHandler(w http.ResponseWriter, req *http.Request) {
	var request RegisterDeviceRequest
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request format")
		return
	}

	// Validate request
	if request.Name == "" {
		respondWithError(w, http.StatusBadRequest, "Device name is required")
		return
	}

	// Map string type to DeviceType enum
	deviceType := device.Generic
	if request.Type == string(device.ESP8266) {
		deviceType = device.ESP8266
	}

	// Register the device
	dev, err := r.app.RegisterDevice(request.Name, deviceType, request.Capabilities, request.Metadata)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to register device: %v", err))
		return
	}

	// Convert to API response format
	response := DeviceResponse{
		ID:              dev.ID,
		Name:            dev.Name,
		Type:            string(dev.Type),
		Status:          string(dev.Status),
		LastSeen:        dev.LastSeen,
		RegisteredAt:    dev.RegisteredAt,
		BlockchainAddr:  dev.BlockchainAddr,
		Capabilities:    dev.Capabilities,
		Metadata:        dev.Metadata,
		FirmwareVersion: dev.FirmwareVersion,
	}

	respondWithJSON(w, http.StatusCreated, response)
}

// GetDeviceHandler returns a specific device by ID
func (r *Router) GetDeviceHandler(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id := vars["id"]

	dev, err := r.app.DeviceRegistry.GetDeviceByID(id)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Device not found")
		return
	}

	// Convert to API response format
	response := DeviceResponse{
		ID:              dev.ID,
		Name:            dev.Name,
		Type:            string(dev.Type),
		Status:          string(dev.Status),
		LastSeen:        dev.LastSeen,
		RegisteredAt:    dev.RegisteredAt,
		BlockchainAddr:  dev.BlockchainAddr,
		Capabilities:    dev.Capabilities,
		Metadata:        dev.Metadata,
		FirmwareVersion: dev.FirmwareVersion,
	}

	respondWithJSON(w, http.StatusOK, response)
}

// UpdateDeviceHandler updates a device
func (r *Router) UpdateDeviceHandler(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id := vars["id"]

	// Check if device exists
	_, err := r.app.DeviceRegistry.GetDeviceByID(id)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Device not found")
		return
	}

	// Parse request body
	var request map[string]interface{}
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request format")
		return
	}

	// Update metadata if provided
	if metadata, ok := request["metadata"].(map[string]interface{}); ok {
		if err := r.app.DeviceRegistry.UpdateDeviceMetadata(id, metadata); err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to update device metadata")
			return
		}
	}

	// Update firmware version if provided
	if firmware, ok := request["firmwareVersion"].(string); ok {
		if err := r.app.DeviceRegistry.UpdateFirmware(id, firmware); err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to update firmware version")
			return
		}
	}

	// Get updated device
	updatedDev, _ := r.app.DeviceRegistry.GetDeviceByID(id)

	// Convert to API response format
	response := DeviceResponse{
		ID:              updatedDev.ID,
		Name:            updatedDev.Name,
		Type:            string(updatedDev.Type),
		Status:          string(updatedDev.Status),
		LastSeen:        updatedDev.LastSeen,
		RegisteredAt:    updatedDev.RegisteredAt,
		BlockchainAddr:  updatedDev.BlockchainAddr,
		Capabilities:    updatedDev.Capabilities,
		Metadata:        updatedDev.Metadata,
		FirmwareVersion: updatedDev.FirmwareVersion,
	}

	respondWithJSON(w, http.StatusOK, response)
}

// DeleteDeviceHandler removes a device
func (r *Router) DeleteDeviceHandler(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id := vars["id"]

	err := r.app.DeviceRegistry.RemoveDevice(id)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Device not found")
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// UpdateDeviceStatusHandler updates a device's status
func (r *Router) UpdateDeviceStatusHandler(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id := vars["id"]

	var request UpdateDeviceStatusRequest
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request format")
		return
	}

	// Map string status to DeviceStatus enum
	var status device.DeviceStatus
	switch request.Status {
	case "Online":
		status = device.Online
	case "Offline":
		status = device.Offline
	case "Suspended":
		status = device.Suspended
	default:
		status = device.Unknown
	}

	err := r.app.DeviceRegistry.UpdateDeviceStatus(id, status)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Device not found")
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// GetDeviceDataHandler returns blockchain data for a specific device
func (r *Router) GetDeviceDataHandler(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id := vars["id"]

	txs, err := r.app.GetDeviceData(id)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Device not found")
		return
	}

	respondWithJSON(w, http.StatusOK, txs)
}

// RegisterESP8266Handler registers a new ESP8266 device
func (r *Router) RegisterESP8266Handler(w http.ResponseWriter, req *http.Request) {
	var request RegisterESP8266Request
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request format")
		return
	}

	// Validate request
	if request.Name == "" {
		respondWithError(w, http.StatusBadRequest, "Device name is required")
		return
	}

	if request.WifiSSID == "" {
		respondWithError(w, http.StatusBadRequest, "WiFi SSID is required")
		return
	}

	// Register ESP8266
	esp, err := r.app.RegisterESP8266(request.Name, request.WifiSSID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to register ESP8266: %v", err))
		return
	}

	// Convert to API response format
	response := DeviceResponse{
		ID:              esp.Device.ID,
		Name:            esp.Device.Name,
		Type:            string(esp.Device.Type),
		Status:          string(esp.Device.Status),
		LastSeen:        esp.Device.LastSeen,
		RegisteredAt:    esp.Device.RegisteredAt,
		BlockchainAddr:  esp.Device.BlockchainAddr,
		Capabilities:    esp.Device.Capabilities,
		Metadata:        esp.Device.Metadata,
		FirmwareVersion: esp.Device.FirmwareVersion,
	}

	// Add ESP8266 specific information to metadata
	if response.Metadata == nil {
		response.Metadata = map[string]interface{}{}
	}
	response.Metadata["wifi_ssid"] = esp.WifiSSID
	response.Metadata["wifi_connected"] = esp.WifiConnected
	response.Metadata["led_state"] = esp.LEDState

	respondWithJSON(w, http.StatusCreated, response)
}

// GetESP8266Handler gets ESP8266 device details
func (r *Router) GetESP8266Handler(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id := vars["id"]

	esp, err := r.app.ESP8266Manager.GetESP8266(id)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "ESP8266 device not found")
		return
	}

	// Convert to API response format with ESP8266 specific fields
	response := map[string]interface{}{
		"id":              esp.Device.ID,
		"name":            esp.Device.Name,
		"type":            string(esp.Device.Type),
		"status":          string(esp.Device.Status),
		"lastSeen":        esp.Device.LastSeen,
		"registeredAt":    esp.Device.RegisteredAt,
		"blockchainAddr":  esp.Device.BlockchainAddr,
		"capabilities":    esp.Device.Capabilities,
		"metadata":        esp.Device.Metadata,
		"firmwareVersion": esp.Device.FirmwareVersion,
		"wifi": map[string]interface{}{
			"ssid":      esp.WifiSSID,
			"connected": esp.WifiConnected,
		},
		"sensors":      esp.SensorReadings,
		"led_state":    esp.LEDState,
		"button_state": esp.ButtonState,
		"last_reading": esp.LastReading,
	}

	respondWithJSON(w, http.StatusOK, response)
}

// SetLEDStateHandler updates the LED state of an ESP8266
func (r *Router) SetLEDStateHandler(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id := vars["id"]

	var request UpdateLEDRequest
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request format")
		return
	}

	// Update LED state
	err := r.app.ESP8266Manager.SetLEDState(id, request.State)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "ESP8266 device not found")
		return
	}

	// Send command to device (would be implemented with MQTT)
	r.app.ESP8266Manager.SendCommand(id, "set_led", map[string]interface{}{
		"state": request.State,
	})

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"state":   request.State,
	})
}

// GetSensorDataHandler returns sensor data for an ESP8266
func (r *Router) GetSensorDataHandler(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id := vars["id"]

	esp, err := r.app.ESP8266Manager.GetESP8266(id)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "ESP8266 device not found")
		return
	}

	respondWithJSON(w, http.StatusOK, esp.SensorReadings)
}

// SendDeviceCommandHandler sends a command to a device
func (r *Router) SendDeviceCommandHandler(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id := vars["id"]

	var request SendCommandRequest
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request format")
		return
	}

	// Validate request
	if request.Command == "" {
		respondWithError(w, http.StatusBadRequest, "Command is required")
		return
	}

	// Check if device exists
	_, err := r.app.DeviceRegistry.GetDeviceByID(id)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Device not found")
		return
	}

	// Send command (depends on device type, using ESP8266 here)
	if err := r.app.ESP8266Manager.SendCommand(id, request.Command, request.Params); err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to send command: %v", err))
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"command": request.Command,
		"params":  request.Params,
	})
}

// UpdateSensorReadingHandler updates a sensor reading for an ESP8266 device
func (r *Router) UpdateSensorReadingHandler(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id := vars["id"]
	sensorType := vars["sensorType"]

	// Parse request body to get sensor value
	var request map[string]float64
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request format")
		return
	}

	value, ok := request["value"]
	if !ok {
		respondWithError(w, http.StatusBadRequest, "Sensor value is required")
		return
	}

	// Update sensor reading
	err := r.app.ESP8266Manager.UpdateSensorReading(id, sensorType, value)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "ESP8266 device not found")
		return
	}

	// Create blockchain transaction for this sensor reading
	data, _ := json.Marshal(map[string]interface{}{
		"sensorType": sensorType,
		"value":      value,
		"timestamp":  time.Now(),
	})

	err = r.app.ProcessDeviceData(id, data)
	if err != nil {
		fmt.Printf("Warning: Failed to record sensor data to blockchain: %v\n", err)
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"sensor":  sensorType,
		"value":   value,
	})
}

// VerifyTransactionHandler verifies a transaction's signature
func (r *Router) VerifyTransactionHandler(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	txID := vars["id"]

	// Look for the transaction in blocks and pending transactions
	var tx *blockchain.Transaction

	// Check pending transactions first
	for i := range r.app.Blockchain.PendingTransactions {
		if r.app.Blockchain.PendingTransactions[i].ID == txID {
			tx = &r.app.Blockchain.PendingTransactions[i]
			break
		}
	}

	// If not found in pending, check blocks
	if tx == nil {
		for _, block := range r.app.Blockchain.Chain {
			for i := range block.Transactions {
				if block.Transactions[i].ID == txID {
					tx = &block.Transactions[i]
					break
				}
			}
			if tx != nil {
				break
			}
		}
	}

	if tx == nil {
		respondWithError(w, http.StatusNotFound, "Transaction not found")
		return
	}

	// Get the sender's public key (in a real implementation, this would be looked up)
	// For this example, we'll request the public key from the device registry
	senderAddr := tx.Sender
	if senderAddr == "SYSTEM" {
		// System transactions are auto-verified
		respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"verified": true,
			"message":  "System transaction is auto-verified",
		})
		return
	}

	// In reality, we would look up the public key for this address
	// (either from the device registry or a dedicated key service)
	device, err := r.app.DeviceRegistry.GetDeviceByBlockchainAddr(senderAddr)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Sender not found")
		return
	}

	// Decode the public key
	publicKey, err := blockchain.DecodePublicKey(device.PublicKey)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to decode public key")
		return
	}

	// Verify the signature
	verified := blockchain.VerifyTransaction(tx, publicKey)

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"verified": verified,
		"txId":     tx.ID,
		"sender":   tx.Sender,
	})
}

// RotateDeviceKeyHandler rotates a device's cryptographic keys
func (r *Router) RotateDeviceKeyHandler(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	deviceID := vars["id"]

	publicKey, err := r.app.DeviceRegistry.RotateDeviceKey(deviceID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	// For security, we only return a fingerprint of the new key, not the key itself
	hashBytes := sha256.Sum256(publicKey)
	fingerprint := fmt.Sprintf("%x", hashBytes[:8])

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":        true,
		"message":        "Device key rotated successfully",
		"keyFingerprint": fingerprint,
	})
}

// AuthMiddleware is middleware that validates JWT tokens
func (r *Router) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Get the JWT token from the Authorization header
		tokenString := req.Header.Get("Authorization")
		if tokenString == "" {
			respondWithError(w, http.StatusUnauthorized, "Authorization token is required")
			return
		}

		// Remove 'Bearer ' prefix if present
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}

		// Parse and validate the token
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(r.config.JWTSecret), nil
		})

		if err != nil || !token.Valid {
			respondWithError(w, http.StatusUnauthorized, "Invalid or expired token")
			return
		}

		// Add claims to request context
		ctx := context.WithValue(req.Context(), "claims", claims)
		next.ServeHTTP(w, req.WithContext(ctx))
	})
}

// DeviceAuthMiddleware validates device API keys
func (r *Router) DeviceAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Get the API key from the X-API-Key header
		apiKey := req.Header.Get("X-API-Key")
		if apiKey == "" {
			respondWithError(w, http.StatusUnauthorized, "API key is required")
			return
		}

		// Validate the API key against device registry
		device, err := r.app.DeviceRegistry.GetDeviceByAPIKey(apiKey)
		if err != nil {
			respondWithError(w, http.StatusUnauthorized, "Invalid API key")
			return
		}

		// Add device to request context
		ctx := context.WithValue(req.Context(), "device", device)
		next.ServeHTTP(w, req.WithContext(ctx))
	})
}

// CORS middleware adds CORS headers to responses
func (r *Router) CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		origin := req.Header.Get("Origin")

		// Check if the origin is allowed
		allowed := false
		for _, allowedOrigin := range r.config.AllowedOrigins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				allowed = true
				break
			}
		}

		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		// Handle preflight requests
		if req.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, req)
	})
}

// LoggingMiddleware logs information about each request
func (r *Router) LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()

		// Create a response writer that captures the status code
		rww := &responseWriterWrapper{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		// Call the next handler
		next.ServeHTTP(rww, req)

		// Log the request
		duration := time.Since(start)
		fmt.Printf("[%s] %s %s %d %s\n",
			time.Now().Format(time.RFC3339),
			req.Method,
			req.URL.Path,
			rww.statusCode,
			duration,
		)
	})
}

// responseWriterWrapper is a wrapper around http.ResponseWriter that captures the status code
type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader captures the status code and calls the wrapped ResponseWriter's WriteHeader
func (rww *responseWriterWrapper) WriteHeader(statusCode int) {
	rww.statusCode = statusCode
	rww.ResponseWriter.WriteHeader(statusCode)
}

// Helper functions for API responses

// respondWithJSON sends a JSON response
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"Internal server error"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

// respondWithError sends an error response
func respondWithError(w http.ResponseWriter, code int, message string) {
	response := APIResponse{
		Success: false,
		Error:   message,
	}
	respondWithJSON(w, code, response)
}
