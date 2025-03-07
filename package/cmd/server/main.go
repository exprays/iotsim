package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"ranger/internal/api"
	"ranger/internal/core"
	"ranger/internal/util/logger"

	"go.uber.org/zap"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "configs/config.yaml", "Path to configuration file")
	logLevel := flag.String("log-level", "", "Override log level (debug, info, warn, error)")
	port := flag.Int("port", 0, "Override API server port")
	flag.Parse()

	// Initialize logger
	log := logger.GetDefaultLogger()
	log.Info("Starting IoT Blockchain API Server")

	// Load config
	log.Info("Loading configuration", zap.String("path", *configPath))
	config, err := core.LoadOrCreateConfig(*configPath)
	if err != nil {
		log.Fatal("Failed to load configuration", zap.Error(err))
	}

	// Override log level if specified
	if *logLevel != "" {
		config.LogLevel = *logLevel
		log.SetLevel(logger.LogLevel(*logLevel))
		log.Info("Log level overridden", zap.String("level", *logLevel))
	}

	// Override port if specified
	if *port > 0 {
		config.API.Port = *port
		log.Info("API port overridden", zap.Int("port", *port))
	}

	// Initialize application
	log.Info("Initializing application")
	app, err := core.NewApp(config)
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
	})

	// Start the application
	if err := app.Start(); err != nil {
		log.Fatal("Failed to start application", zap.Error(err))
	}

	// Create API router
	router := api.SetupRouter(app, config.API.JWTSecret, config.API.AllowedOrigins)

	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", config.API.Host, config.API.Port),
		Handler:      router,
		ReadTimeout:  time.Second * 15,
		WriteTimeout: time.Second * 15,
		IdleTimeout:  time.Second * 60,
	}

	// Start the server in a goroutine
	go func() {
		log.Info("API server listening",
			zap.String("address", server.Addr),
			zap.Bool("auth_enabled", config.API.AuthEnabled),
		)

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("API server failed", zap.Error(err))
		}
	}()

	// Start web dashboard if enabled
	if config.Web.Enabled {
		log.Info("Starting web dashboard",
			zap.String("address", fmt.Sprintf("%s:%d", config.Web.Host, config.Web.Port)),
		)
		// Web dashboard implementation would be initialized here
	}

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Info("Shutting down server", zap.String("signal", sig.String()))

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Shutdown the server
	if err := server.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown", zap.Error(err))
	}

	// Stop the application
	if err := app.Stop(); err != nil {
		log.Fatal("Failed to stop application", zap.Error(err))
	}

	log.Info("Server exited gracefully")
}

func setupDirectories(config *core.Config) error {
	dirs := []string{
		filepath.Dir(config.Blockchain.PersistPath),
		filepath.Dir(config.Device.RegistryPath),
		"./logs",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

func loadConfig() *core.Config {
	// Load from file or environment
	config := &core.Config{}
	// ... existing code ...

	// Set defaults if not loaded
	if config.Device.KeyStorePath == "" {
		// Default to a subdirectory of the data directory
		config.Device.KeyStorePath = filepath.Join("data", "keystore.dat")
	}

	if config.Device.KeyFormat == "" {
		config.Device.KeyFormat = "PKCS8" // Default key format
	}

	return config
}
