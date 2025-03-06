package core

import (
	"context"
	"fmt"
	"sync"
	"time"

	"ranger/internal/blockchain"
	"ranger/internal/device"
)

// Application states
const (
	StatusInitializing = "initializing"
	StatusRunning      = "running"
	StatusStopping     = "stopping"
	StatusStopped      = "stopped"
	StatusError        = "error"
)

// App represents the core application that integrates all components
type App struct {
	// Core components
	Config         *Config
	Blockchain     *blockchain.Blockchain
	DeviceRegistry *device.DeviceRegistry
	ESP8266Manager *device.ESP8266Manager

	// App status
	Status       string
	startTime    time.Time
	stopTime     time.Time
	lastError    error
	mu           sync.RWMutex
	stopChan     chan struct{}
	wg           sync.WaitGroup
	ctx          context.Context
	cancelFunc   context.CancelFunc
	eventHandler func(eventType string, data interface{})
}

// NewApp creates a new application instance
func NewApp(config *Config) (*App, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	ctx, cancel := context.WithCancel(context.Background())

	app := &App{
		Config:     config,
		Status:     StatusInitializing,
		stopChan:   make(chan struct{}),
		ctx:        ctx,
		cancelFunc: cancel,
	}

	return app, nil
}

// Initialize sets up all components of the application
func (a *App) Initialize() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Initialize blockchain
	a.Blockchain = blockchain.NewBlockchain(
		a.Config.Blockchain.Difficulty,
		a.Config.Blockchain.MiningReward,
	)

	// Initialize device registry
	a.DeviceRegistry = device.NewDeviceRegistry()

	// Initialize ESP8266 manager
	a.ESP8266Manager = device.NewESP8266Manager(a.DeviceRegistry)

	// Set up event handling
	go a.processEvents()

	return nil
}

// Start launches the application and all its components
func (a *App) Start() error {
	a.mu.Lock()
	if a.Status == StatusRunning {
		a.mu.Unlock()
		return fmt.Errorf("application is already running")
	}

	a.Status = StatusRunning
	a.startTime = time.Now()
	a.mu.Unlock()

	// Start blockchain transaction processor
	a.wg.Add(1)
	go a.processBlockchainTransactions()

	// Start device status monitor
	a.wg.Add(1)
	go a.monitorDeviceStatus()

	// Log application start
	if a.Config.Debug {
		fmt.Printf("[%s] Application started with configuration: %+v\n",
			time.Now().Format(time.RFC3339), a.Config)
	}

	return nil
}

// Stop gracefully shuts down the application
func (a *App) Stop() error {
	a.mu.Lock()
	if a.Status == StatusStopped || a.Status == StatusStopping {
		a.mu.Unlock()
		return nil
	}

	a.Status = StatusStopping
	a.mu.Unlock()

	// Signal all goroutines to stop
	a.cancelFunc()
	close(a.stopChan)

	// Wait for all goroutines to complete with timeout
	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All goroutines completed
	case <-time.After(5 * time.Second):
		fmt.Println("Warning: Some goroutines did not stop gracefully")
	}

	a.mu.Lock()
	a.Status = StatusStopped
	a.stopTime = time.Now()
	a.mu.Unlock()

	return nil
}

// GetStatus returns the current application status
func (a *App) GetStatus() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.Status
}

// GetUptime returns the application uptime
func (a *App) GetUptime() time.Duration {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.Status == StatusStopped {
		return a.stopTime.Sub(a.startTime)
	}
	return time.Since(a.startTime)
}

// SetEventHandler sets the function to be called on system events
func (a *App) SetEventHandler(handler func(eventType string, data interface{})) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.eventHandler = handler
}

// RegisterDevice registers a new device and connects it to the blockchain
func (a *App) RegisterDevice(name string, deviceType device.DeviceType,
	capabilities []string, metadata map[string]interface{}) (*device.Device, error) {

	// Register device with registry
	dev, err := a.DeviceRegistry.RegisterDevice(name, deviceType, capabilities, metadata)
	if err != nil {
		return nil, err
	}

	// Log device registration
	a.emitEvent("device_registered", map[string]interface{}{
		"device_id": dev.ID,
		"name":      dev.Name,
		"type":      dev.Type,
	})

	return dev, nil
}

// RegisterESP8266 registers a new ESP8266 device
func (a *App) RegisterESP8266(name string, wifiSSID string) (*device.ESP8266Device, error) {
	return a.ESP8266Manager.RegisterESP8266(name, wifiSSID)
}

// ProcessDeviceData processes data received from a device and adds it to the blockchain
func (a *App) ProcessDeviceData(deviceID string, data []byte) error {
	// Get device from registry
	dev, err := a.DeviceRegistry.GetDeviceByID(deviceID)
	if err != nil {
		return err
	}

	// Create a blockchain transaction for this data
	tx := blockchain.NewTransaction(
		fmt.Sprintf("data-%d", time.Now().UnixNano()),
		dev.BlockchainAddr,
		"SYSTEM",
		data,
	)

	// Add transaction to blockchain
	err = a.Blockchain.AddTransaction(tx)
	if err != nil {
		return err
	}

	// If we have enough pending transactions, trigger mining
	if a.Blockchain.GetPendingTransactionsCount() >= a.Config.Blockchain.TransactionsPerBlock {
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			_, err := a.Blockchain.MineBlock("SYSTEM")
			if err != nil {
				fmt.Printf("Mining error: %v\n", err)
			} else if a.Config.Debug {
				fmt.Println("New block mined and added to the blockchain")
			}
		}()
	}

	return nil
}

// GetDeviceData retrieves all blockchain transactions for a specific device
func (a *App) GetDeviceData(deviceID string) ([]blockchain.Transaction, error) {
	// Get device from registry
	dev, err := a.DeviceRegistry.GetDeviceByID(deviceID)
	if err != nil {
		return nil, err
	}

	// Get transactions from blockchain
	return a.Blockchain.GetTransactionsByAddress(dev.BlockchainAddr), nil
}

// Private helper methods

// processEvents handles device events and forwards them to the event handler
func (a *App) processEvents() {
	deviceEvents := a.DeviceRegistry.EventChannel()

	for {
		select {
		case event := <-deviceEvents:
			// Process device event
			if a.eventHandler != nil {
				a.eventHandler(event.Type, event)
			}

		case <-a.stopChan:
			return
		}
	}
}

// processBlockchainTransactions periodically checks and mines pending transactions
func (a *App) processBlockchainTransactions() {
	defer a.wg.Done()

	ticker := time.NewTicker(time.Duration(a.Config.Blockchain.MiningInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if a.Blockchain.GetPendingTransactionsCount() > 0 {
				_, err := a.Blockchain.MineBlock("SYSTEM")
				if err != nil {
					a.mu.Lock()
					a.lastError = err
					a.mu.Unlock()

					if a.Config.Debug {
						fmt.Printf("Mining error: %v\n", err)
					}
				} else if a.Config.Debug {
					fmt.Println("New block mined and added to the blockchain")
				}
			}

		case <-a.ctx.Done():
			return

		case <-a.stopChan:
			return
		}
	}
}

// monitorDeviceStatus regularly updates device status based on last seen time
func (a *App) monitorDeviceStatus() {
	defer a.wg.Done()

	ticker := time.NewTicker(time.Duration(a.Config.Device.StatusCheckInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			devices := a.DeviceRegistry.ListDevices()
			now := time.Now()

			for _, dev := range devices {
				if dev.Status != device.Offline && dev.Status != device.Suspended {
					// Check if device has timed out
					if now.Sub(dev.LastSeen) > time.Duration(a.Config.Device.DeviceTimeoutSeconds)*time.Second {
						a.DeviceRegistry.UpdateDeviceStatus(dev.ID, device.Offline)

						if a.Config.Debug {
							fmt.Printf("Device %s (%s) is now offline due to timeout\n", dev.ID, dev.Name)
						}
					}
				}
			}

		case <-a.ctx.Done():
			return

		case <-a.stopChan:
			return
		}
	}
}

// emitEvent sends an event to the event handler if one is registered
func (a *App) emitEvent(eventType string, data interface{}) {
	a.mu.RLock()
	handler := a.eventHandler
	a.mu.RUnlock()

	if handler != nil {
		handler(eventType, data)
	}
}
