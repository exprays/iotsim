package main

import (
	"bufio"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"ranger/internal/blockchain"
	"ranger/internal/core"
	"ranger/internal/device"
	"ranger/internal/util/logger"

	"github.com/fatih/color"
	"go.uber.org/zap"
)

var (
	app       *core.App
	log       *logger.Logger
	config    *core.Config
	bold      = color.New(color.Bold)
	green     = color.New(color.FgGreen)
	yellow    = color.New(color.FgYellow)
	red       = color.New(color.FgRed)
	blue      = color.New(color.FgBlue)
	magenta   = color.New(color.FgMagenta)
	cyan      = color.New(color.FgCyan)
	boldGreen = color.New(color.FgGreen, color.Bold)
	boldRed   = color.New(color.FgRed, color.Bold)
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "configs/config.yaml", "Path to configuration file")
	logLevel := flag.String("log-level", "", "Override log level (debug, info, warn, error)")
	interactive := flag.Bool("interactive", true, "Run in interactive mode")
	command := flag.String("command", "", "Run a specific command and exit")
	flag.Parse()

	// Initialize logger
	log = logger.GetDefaultLogger()
	log.Info("IoT Blockchain CLI Starting")

	// Display welcome banner
	printWelcomeBanner()

	// Load config
	log.Info("Loading configuration", zap.String("path", *configPath))
	var err error
	config, err = core.LoadOrCreateConfig(*configPath)
	if err != nil {
		log.Fatal("Failed to load configuration", zap.Error(err))
	}

	// Override log level if specified
	if *logLevel != "" {
		config.LogLevel = *logLevel
		log.SetLevel(logger.LogLevel(*logLevel))
		log.Info("Log level overridden", zap.String("level", *logLevel))
	}

	// Initialize application
	log.Info("Initializing application")
	app, err = core.NewApp(config)
	if err != nil {
		log.Fatal("Failed to create application", zap.Error(err))
	}

	// Initialize components
	if err := app.Initialize(); err != nil {
		log.Fatal("Failed to initialize application", zap.Error(err))
	}

	// Set up event handler
	app.SetEventHandler(func(eventType string, data interface{}) {
		log.Info("Event received",
			zap.String("type", eventType),
			zap.Any("data", data),
		)

		// Print notification for important events
		switch eventType {
		case "DEVICE_REGISTERED":
			fmt.Printf("📱 New device registered: %v\n", data)
		case "BLOCK_MINED":
			fmt.Printf("⛓️ New block mined: %v\n", data)
		}
	})

	// Start the application
	if err := app.Start(); err != nil {
		log.Fatal("Failed to start application", zap.Error(err))
	}

	// Run in interactive mode or execute single command
	if *interactive && *command == "" {
		runInteractiveMode()
	} else if *command != "" {
		executeCommand(*command, []string{})
	} else {
		log.Fatal("Must specify either interactive mode or a command to run")
	}

	// Cleanup
	if err := app.Stop(); err != nil {
		log.Fatal("Failed to stop application", zap.Error(err))
	}

	log.Info("CLI exited gracefully")
}

func printWelcomeBanner() {
	fmt.Println()
	boldGreen.Println("╔══════════════════════════════════════════════╗")
	boldGreen.Println("║         IOT BLOCKCHAIN TOOLKIT CLI           ║")
	boldGreen.Println("╚══════════════════════════════════════════════╝")
	fmt.Println("    Secure IoT Data with Blockchain Technology")
	fmt.Printf("    Version 1.0.0 | %s\n\n", time.Now().Format("2006-01-02"))
}

func runInteractiveMode() {
	reader := bufio.NewReader(os.Stdin)

	for {
		bold.Print("\niot-blockchain> ")
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading input:", err)
			continue
		}

		input = strings.TrimSpace(input)
		parts := strings.Fields(input)

		if len(parts) == 0 {
			continue
		}

		command := strings.ToLower(parts[0])

		if command == "exit" || command == "quit" {
			break
		}

		args := []string{}
		if len(parts) > 1 {
			args = parts[1:]
		}
		executeCommand(command, args)
	}
}

// Update the main command handler function
func executeCommand(command string, args []string) {
	switch command {
	case "status":
		showStatus()
	case "device", "devices":
		handleDeviceCommand(args[0], args[1:])
	case "blockchain":
		handleBlockchainCommand(args[0], args[1:])
	case "mine":
		mineBlock()
	case "validate":
		validateBlockchain()
	case "keys", "key":
		handleKeyCommand(args[0], args[1:])
	case "exit", "quit":
		fmt.Println("Exiting.")
		os.Exit(0)
	default:
		fmt.Printf("Unknown command: %s\n", command)
	}
}

func showHelp() {
	bold.Println("\nAvailable Commands:")

	fmt.Println("\n🔷 General Commands:")
	fmt.Println("  help                   - Show this help message")
	fmt.Println("  status                 - Show system status")
	fmt.Println("  exit, quit             - Exit the application")

	fmt.Println("\n🔷 Device Commands:")
	fmt.Println("  devices                - List all registered devices")
	fmt.Println("  devices info [id]      - Show details for a specific device")
	fmt.Println("  devices delete [id]    - Delete a device")
	fmt.Println("  register device [name] - Register a new generic device")
	fmt.Println("  register esp8266 [name] [wifi-ssid] - Register a new ESP8266 device")
	fmt.Println("  send [id] [cmd] [params] - Send command to a device")

	fmt.Println("\n🔷 Blockchain Commands:")
	fmt.Println("  blockchain             - Show blockchain status")
	fmt.Println("  blockchain blocks      - List recent blocks")
	fmt.Println("  blockchain txs         - List recent transactions")
	fmt.Println("  mine                   - Mine a new block")
	fmt.Println("  validate               - Validate blockchain integrity")

	fmt.Println("\n🔷 Key Management Commands:")
	fmt.Println("  keys list              - List all device keys")
	fmt.Println("  keys rotate [device-id] - Rotate device key")
	fmt.Println("  keys export [device-id] - Export device public key")

	fmt.Println()
}

func showStatus() {
	bold.Println("\n📊 System Status")
	fmt.Printf("Status: %s\n", green.Sprint(app.GetStatus()))
	fmt.Printf("Uptime: %s\n", app.GetUptime().Round(time.Second))
	fmt.Printf("Blockchain: %d blocks, %d pending transactions\n",
		app.Blockchain.GetChainLength(),
		app.Blockchain.GetPendingTransactionsCount())

	devices := app.DeviceRegistry.ListDevices()
	onlineCount := 0
	for _, dev := range devices {
		if dev.Status == device.Online {
			onlineCount++
		}
	}

	fmt.Printf("Devices: %d total, %d online\n", len(devices), onlineCount)

	// Check blockchain validity
	isValid := app.Blockchain.ValidateChain()
	if isValid {
		fmt.Printf("Blockchain integrity: %s\n", green.Sprint("Valid"))
	} else {
		fmt.Printf("Blockchain integrity: %s\n", red.Sprint("Invalid"))
	}
}

func listDevices() {
	devices := app.DeviceRegistry.ListDevices()

	bold.Println("\n📱 Registered Devices")
	if len(devices) == 0 {
		fmt.Println("No devices registered yet.")
		return
	}

	fmt.Printf("\n%-36s %-20s %-10s %-20s\n", "ID", "NAME", "TYPE", "STATUS")
	fmt.Println(strings.Repeat("-", 90))

	for _, dev := range devices {
		status := string(dev.Status)
		statusColored := status

		switch dev.Status {
		case device.Online:
			statusColored = green.Sprint(status)
		case device.Offline:
			statusColored = yellow.Sprint(status)
		case device.Suspended:
			statusColored = red.Sprint(status)
		}

		fmt.Printf("%-36s %-20s %-10s %-20s\n", dev.ID, dev.Name, dev.Type, statusColored)
	}
}

func handleDeviceCommand(subCommand string, args []string) {
	switch subCommand {
	case "info":
		if len(args) > 0 {
			showDeviceInfo(args[0])
		} else {
			fmt.Println("Usage: devices info [device-id]")
		}
	case "delete":
		if len(args) > 0 {
			deleteDevice(args[0])
		} else {
			fmt.Println("Usage: devices delete [device-id]")
		}
	default:
		fmt.Printf("Unknown devices subcommand: %s\n", subCommand)
	}
}

func showDeviceInfo(deviceID string) {
	dev, err := app.DeviceRegistry.GetDeviceByID(deviceID)
	if err != nil {
		red.Printf("Error: %v\n", err)
		return
	}

	bold.Println("\n📱 Device Information")
	fmt.Printf("ID: %s\n", dev.ID)
	fmt.Printf("Name: %s\n", dev.Name)
	fmt.Printf("Type: %s\n", dev.Type)
	fmt.Printf("Status: %s\n", dev.Status)
	fmt.Printf("Last seen: %s\n", dev.LastSeen.Format(time.RFC3339))
	fmt.Printf("Registered at: %s\n", dev.RegisteredAt.Format(time.RFC3339))
	fmt.Printf("Blockchain address: %s\n", dev.BlockchainAddr)

	if len(dev.Capabilities) > 0 {
		fmt.Println("\nCapabilities:")
		for _, cap := range dev.Capabilities {
			fmt.Printf("  - %s\n", cap)
		}
	}

	if dev.Metadata != nil && len(dev.Metadata) > 0 {
		fmt.Println("\nMetadata:")
		for key, value := range dev.Metadata {
			fmt.Printf("  %s: %v\n", key, value)
		}
	}

	// If it's an ESP8266, get more details
	if dev.Type == device.ESP8266 {
		esp, err := app.ESP8266Manager.GetESP8266(deviceID)
		if err == nil {
			fmt.Println("\nESP8266 Specific Information:")
			fmt.Printf("  WiFi SSID: %s\n", esp.WifiSSID)
			fmt.Printf("  WiFi Connected: %v\n", esp.WifiConnected)
			fmt.Printf("  LED State: %v\n", esp.LEDState)
			fmt.Printf("  Button State: %v\n", esp.ButtonState)

			if len(esp.SensorReadings) > 0 {
				fmt.Println("\n  Sensor Readings:")
				for sensor, value := range esp.SensorReadings {
					fmt.Printf("    %s: %.2f\n", sensor, value)
				}
			}
		}
	}

	// Show blockchain transactions for this device
	transactions, err := app.GetDeviceData(deviceID)
	if err == nil && len(transactions) > 0 {
		fmt.Printf("\nRecent Blockchain Transactions (%d):\n", len(transactions))
		for i, tx := range transactions {
			if i >= 5 { // Show only the 5 most recent
				fmt.Printf("  ... and %d more\n", len(transactions)-5)
				break
			}
			fmt.Printf("  %s: %s\n", tx.ID[:8], time.Time(tx.Timestamp).Format(time.RFC3339))
		}
	}
}

func deleteDevice(deviceID string) {
	err := app.DeviceRegistry.RemoveDevice(deviceID)
	if err != nil {
		red.Printf("Error: %v\n", err)
		return
	}

	green.Printf("Device %s successfully deleted.\n", deviceID)
}

func showBlockchainStatus() {
	chainLength := app.Blockchain.GetChainLength()
	pendingTx := app.Blockchain.GetPendingTransactionsCount()
	isValid := app.Blockchain.ValidateChain()

	bold.Println("\n⛓️ Blockchain Status")
	fmt.Printf("Blocks: %d\n", chainLength)
	fmt.Printf("Pending transactions: %d\n", pendingTx)
	fmt.Printf("Difficulty: %d\n", app.Blockchain.Difficulty)

	var integrityStatus string
	if isValid {
		integrityStatus = green.Sprint("Valid")
	} else {
		integrityStatus = red.Sprint("Invalid")
	}
	fmt.Printf("Integrity: %s\n", integrityStatus)

	if chainLength > 0 {
		lastBlock := app.Blockchain.Chain[chainLength-1]
		fmt.Printf("\nLatest block:\n")
		fmt.Printf("  Hash: %s\n", lastBlock.Hash)
		fmt.Printf("  Index: %d\n", lastBlock.Index)
		fmt.Printf("  Time: %s\n", lastBlock.Timestamp.Format(time.RFC3339))
		fmt.Printf("  Transactions: %d\n", len(lastBlock.Transactions))
	}
}

func handleBlockchainCommand(subCommand string, args []string) {
	switch subCommand {
	case "blocks":
		listBlocks()
	case "txs", "transactions":
		listTransactions()
	default:
		fmt.Printf("Unknown blockchain subcommand: %s\n", subCommand)
	}
}

func listBlocks() {
	chainLength := app.Blockchain.GetChainLength()
	if chainLength == 0 {
		fmt.Println("No blocks in the blockchain yet.")
		return
	}

	bold.Println("\n⛓️ Recent Blocks")
	fmt.Printf("\n%-6s %-20s %-10s %-64s\n", "INDEX", "TIMESTAMP", "TXS", "HASH")
	fmt.Println(strings.Repeat("-", 100))

	// Show the 10 most recent blocks
	start := chainLength - 1
	end := start - 10
	if end < 0 {
		end = 0
	}

	for i := start; i >= end; i-- {
		block := app.Blockchain.Chain[i]
		fmt.Printf("%-6d %-20s %-10d %.62s...\n",
			block.Index,
			block.Timestamp.Format("2006-01-02 15:04:05"),
			len(block.Transactions),
			block.Hash)
	}
}

func listTransactions() {
	txs := []blockchain.Transaction{}

	for _, block := range app.Blockchain.Chain {
		for _, tx := range block.Transactions {
			txs = append(txs, tx)
		}
	}

	// Add pending transactions
	for _, tx := range app.Blockchain.PendingTransactions {
		txs = append(txs, tx)
	}

	if len(txs) == 0 {
		fmt.Println("No transactions in the blockchain yet.")
		return
	}

	bold.Println("\n💸 Recent Transactions")
	fmt.Printf("\n%-10s %-20s %-20s %-20s %-10s\n", "ID", "TIMESTAMP", "SENDER", "RECIPIENT", "VERIFIED")
	fmt.Println(strings.Repeat("-", 90))

	// Show the 10 most recent transactions
	count := 0
	for i := len(txs) - 1; i >= 0 && count < 10; i-- {
		tx := txs[i]
		verifiedStatus := "❌"
		if tx.Verified {
			verifiedStatus = "✅"
		}

		// Truncate IDs for display
		senderID := tx.Sender
		if len(senderID) > 15 {
			senderID = senderID[:12] + "..."
		}

		recipientID := tx.Recipient
		if len(recipientID) > 15 {
			recipientID = recipientID[:12] + "..."
		}

		txID := tx.ID
		if len(txID) > 8 {
			txID = txID[:8]
		}

		fmt.Printf("%-10s %-20s %-20s %-20s %-10s\n",
			txID,
			tx.Timestamp.Format("2006-01-02 15:04:05"),
			senderID,
			recipientID,
			verifiedStatus)

		count++
	}
}

func handleRegisterCommand(deviceType string, args []string) {
	switch deviceType {
	case "device":
		if len(args) > 0 {
			registerGenericDevice(args[0])
		} else {
			fmt.Println("Usage: register device [name]")
		}
	case "esp8266":
		if len(args) >= 2 {
			registerESP8266Device(args[0], args[1])
		} else {
			fmt.Println("Usage: register esp8266 [name] [wifi-ssid]")
		}
	default:
		fmt.Printf("Unknown device type: %s\n", deviceType)
	}
}

func registerGenericDevice(name string) {
	capabilities := []string{"data_storage", "blockchain_integration"}
	metadata := map[string]interface{}{
		"registered_by": "cli",
		"timestamp":     time.Now(),
	}

	dev, err := app.RegisterDevice(name, device.Generic, capabilities, metadata)
	if err != nil {
		red.Printf("Error: %v\n", err)
		return
	}

	green.Printf("Device successfully registered!\n")
	fmt.Printf("ID: %s\n", dev.ID)
	fmt.Printf("API Key: %s\n", dev.APIKey)
	fmt.Printf("Blockchain Address: %s\n", dev.BlockchainAddr)
}

func registerESP8266Device(name string, wifiSSID string) {
	esp, err := app.RegisterESP8266(name, wifiSSID)
	if err != nil {
		red.Printf("Error: %v\n", err)
		return
	}

	green.Printf("ESP8266 device successfully registered!\n")
	fmt.Printf("ID: %s\n", esp.Device.ID)
	fmt.Printf("API Key: %s\n", esp.Device.APIKey)
	fmt.Printf("Blockchain Address: %s\n", esp.Device.BlockchainAddr)
	fmt.Printf("WiFi SSID: %s\n", esp.WifiSSID)
}

func mineBlock() {
	pendingTx := app.Blockchain.GetPendingTransactionsCount()
	if pendingTx == 0 {
		yellow.Println("No pending transactions to mine.")
		return
	}

	fmt.Printf("Mining a new block with %d pending transactions...\n", pendingTx)

	block, err := app.Blockchain.MineBlock("CLI_MINER")
	if err != nil {
		red.Printf("Mining failed: %v\n", err)
		return
	}

	green.Printf("Block successfully mined!\n")
	fmt.Printf("Block hash: %s\n", block.Hash)
	fmt.Printf("Block index: %d\n", block.Index)
	fmt.Printf("Transactions: %d\n", len(block.Transactions))
}

func validateBlockchain() {
	isValid := app.Blockchain.ValidateChain()
	if isValid {
		green.Println("Blockchain is valid! All blocks properly linked and hashed.")
	} else {
		red.Println("Blockchain validation FAILED! Chain integrity is compromised.")
	}
}

func sendCommand(deviceID, command string, params []string) {
	// Parse params into map
	paramsMap := make(map[string]interface{})
	for i := 0; i < len(params); i += 2 {
		if i+1 < len(params) {
			paramsMap[params[i]] = params[i+1]
		}
	}

	// Check if device exists
	_, err := app.DeviceRegistry.GetDeviceByID(deviceID)
	if err != nil {
		red.Printf("Error: Device not found with ID %s\n", deviceID)
		return
	}

	// For ESP8266 devices, handle special commands
	if command == "led" && len(params) >= 1 {
		state := strings.ToLower(params[0]) == "on" || params[0] == "true" || params[0] == "1"
		err = app.ESP8266Manager.SetLEDState(deviceID, state)
		if err == nil {
			green.Printf("LED state for device %s set to: %v\n", deviceID, state)
		} else {
			red.Printf("Error: %v\n", err)
		}
		return
	}

	// Send generic command
	err = app.ESP8266Manager.SendCommand(deviceID, command, paramsMap)
	if err != nil {
		red.Printf("Error: %v\n", err)
		return
	}

	green.Printf("Command '%s' sent to device %s with parameters: %v\n",
		command, deviceID, paramsMap)
}

func handleKeyCommand(subCommand string, args []string) {
	switch subCommand {
	case "list":
		listDeviceKeys()
	case "rotate":
		if len(args) < 1 {
			fmt.Println("Usage: keys rotate <device-id>")
			return
		}
		rotateDeviceKey(args[0])
	case "export":
		if len(args) < 1 {
			fmt.Println("Usage: keys export <device-id>")
			return
		}
		exportDevicePublicKey(args[0])
	default:
		fmt.Printf("Unknown key subcommand: %s\n", subCommand)
	}
}

func listDeviceKeys() {
	devices := app.DeviceRegistry.ListDevices()

	if len(devices) == 0 {
		fmt.Println("No devices registered.")
		return
	}

	bold.Println("\n🔑 Device Keys")
	fmt.Printf("\n%-36s %-20s %-40s\n", "DEVICE ID", "NAME", "BLOCKCHAIN ADDRESS")
	fmt.Println(strings.Repeat("-", 100))

	for _, dev := range devices {
		fmt.Printf("%-36s %-20s %-40s\n",
			dev.ID,
			dev.Name,
			dev.BlockchainAddr)
	}
}

func rotateDeviceKey(deviceID string) {
	fmt.Printf("Rotating key for device %s...\n", deviceID)

	// Get the device first to verify it exists
	device, err := app.DeviceRegistry.GetDeviceByID(deviceID)
	if err != nil {
		red.Printf("Error: %v\n", err)
		return
	}

	// Call the key rotation API
	publicKey, err := app.DeviceRegistry.RotateDeviceKey(deviceID)
	if err != nil {
		red.Printf("Failed to rotate key: %v\n", err)
		return
	}

	green.Println("Key rotated successfully!")
	fmt.Printf("Device: %s (%s)\n", device.Name, device.ID)
	hash := sha256.Sum256(publicKey)
	fmt.Printf("New public key fingerprint: %x\n", hash[:8])
}

func exportDevicePublicKey(deviceID string) {
	device, err := app.DeviceRegistry.GetDeviceByID(deviceID)
	if err != nil {
		red.Printf("Error: %v\n", err)
		return
	}

	if device.PublicKey == nil || len(device.PublicKey) == 0 {
		red.Println("Device has no public key.")
		return
	}

	outputFile := fmt.Sprintf("%s_pubkey.pem", deviceID)
	if err := os.WriteFile(outputFile, device.PublicKey, 0644); err != nil {
		red.Printf("Failed to export key: %v\n", err)
		return
	}

	green.Printf("Public key exported to %s\n", outputFile)
}
