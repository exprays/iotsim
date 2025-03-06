package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/yourusername/iot-blockchain-toolkit/internal/core"
	"github.com/yourusername/iot-blockchain-toolkit/internal/util/logger"
)

var (
	port           = flag.Int("port", 8080, "Server port")
	configFile     = flag.String("config", "./config.yaml", "Configuration file path")
	logLevel       = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	blockchainPath = flag.String("blockchain", "./data/blockchain", "Blockchain data directory")
	deviceDbPath   = flag.String("devicedb", "./data/devices.db", "Device database path")
)

func main() {
	flag.Parse()

	// Set up logging
	logger.SetLevel(*logLevel)
	log := logger.GetLogger("server")
	log.Info("IoT Blockchain API Server starting...")

	// Load configuration
	config, err := core.LoadConfig(*configFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Info("Configuration file not found, using defaults")
			config = core.DefaultConfig()
		} else {
			log.Fatalf("Error loading configuration: %v", err)
		}
	}

	// Override config with command line flags if provided
	if flag.Lookup("port").Changed {
		config.Server.Port = *port
	}
	if flag.Lookup("blockchain").Changed {
		config.Blockchain.DataPath = *blockchainPath
	}
	if flag.Lookup("devicedb").Changed {
		config.DeviceRegistry.DbPath = *deviceDbPath
	}

	// Create application instance
	app, err := core.NewApp(config)
	if err != nil {
		log.Fatalf("Failed to initialize application: %v", err)
	}

	// Set up signal handling for graceful shutdown
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-signalCh
		log.Infof("Received signal: %v", sig)
		app.Shutdown()
		os.Exit(0)
	}()

	// Start the server
	log.Infof("Starting server on port %d", config.Server.Port)
	if err := app.StartServer(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
