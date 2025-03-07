package core

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

// Config represents the application configuration
type Config struct {
	Debug      bool             `json:"debug" yaml:"debug"`
	LogLevel   string           `json:"logLevel" yaml:"logLevel"`
	Blockchain BlockchainConfig `json:"blockchain" yaml:"blockchain"`
	Device     DeviceConfig     `json:"device" yaml:"device"`
	API        APIConfig        `json:"api" yaml:"api"`
	MQTT       MQTTConfig       `json:"mqtt" yaml:"mqtt"`
	Web        WebConfig        `json:"web" yaml:"web"`
}

// BlockchainConfig holds blockchain-specific configuration
type BlockchainConfig struct {
	Difficulty           uint8   `json:"difficulty" yaml:"difficulty"`
	MiningReward         float64 `json:"miningReward" yaml:"miningReward"`
	MiningInterval       int     `json:"miningInterval" yaml:"miningInterval"`
	TransactionsPerBlock int     `json:"transactionsPerBlock" yaml:"transactionsPerBlock"`
	PersistPath          string  `json:"persistPath" yaml:"persistPath"`
}

// DeviceConfig holds device-related settings
type DeviceConfig struct {
	RegistryPath         string `json:"registry_path" yaml:"registry_path"`
	StatusCheckInterval  int    `json:"status_check_interval" yaml:"status_check_interval"`
	DeviceTimeoutSeconds int    `json:"device_timeout_seconds" yaml:"device_timeout_seconds"`
	KeyStorePath         string `json:"key_store_path" yaml:"key_store_path"`
	KeyFormat            string `json:"key_format" yaml:"key_format"`
}

// APIConfig holds API-specific configuration
type APIConfig struct {
	Enabled        bool     `json:"enabled" yaml:"enabled"`
	Host           string   `json:"host" yaml:"host"`
	Port           int      `json:"port" yaml:"port"`
	AuthEnabled    bool     `json:"authEnabled" yaml:"authEnabled"`
	JWTSecret      string   `json:"jwtSecret" yaml:"jwtSecret"`
	AllowedOrigins []string `json:"allowedOrigins" yaml:"allowedOrigins"`
}

// MQTTConfig holds MQTT-specific configuration
type MQTTConfig struct {
	Enabled   bool   `json:"enabled" yaml:"enabled"`
	Broker    string `json:"broker" yaml:"broker"`
	Port      int    `json:"port" yaml:"port"`
	ClientID  string `json:"clientId" yaml:"clientId"`
	Username  string `json:"username" yaml:"username"`
	Password  string `json:"password" yaml:"password"`
	TopicRoot string `json:"topicRoot" yaml:"topicRoot"`
	QoS       int    `json:"qos" yaml:"qos"`
}

// WebConfig holds web dashboard configuration
type WebConfig struct {
	Enabled bool   `json:"enabled" yaml:"enabled"`
	Host    string `json:"host" yaml:"host"`
	Port    int    `json:"port" yaml:"port"`
	Title   string `json:"title" yaml:"title"`
}

// LoadConfig loads configuration from a file
func LoadConfig(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	config := DefaultConfig()

	// Determine file type by extension
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		if err := json.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("error parsing JSON config: %w", err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("error parsing YAML config: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported config file format: %s", ext)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

// DefaultConfig creates a configuration with default values
func DefaultConfig() *Config {
	return &Config{
		Debug:    false,
		LogLevel: "info",
		Blockchain: BlockchainConfig{
			Difficulty:           4,
			MiningReward:         1.0,
			MiningInterval:       30,
			TransactionsPerBlock: 5,
			PersistPath:          "./data/blockchain",
		},
		Device: DeviceConfig{
			RegistryPath:         "./data/devices.json",
			DeviceTimeoutSeconds: 300,
			StatusCheckInterval:  60,
			KeyStorePath:         "./data/keystore",
			KeyFormat:            "pem",
		},
		API: APIConfig{
			Enabled:        true,
			Host:           "0.0.0.0",
			Port:           8080,
			AuthEnabled:    true,
			JWTSecret:      generateDefaultSecret(),
			AllowedOrigins: []string{"*"},
		},
		MQTT: MQTTConfig{
			Enabled:   true,
			Broker:    "localhost",
			Port:      1883,
			ClientID:  "iot-blockchain-toolkit",
			Username:  "",
			Password:  "",
			TopicRoot: "iot-blockchain",
			QoS:       1,
		},
		Web: WebConfig{
			Enabled: true,
			Host:    "0.0.0.0",
			Port:    8081,
			Title:   "IoT Blockchain Toolkit",
		},
	}
}

// Validate checks the configuration for errors
func (c *Config) Validate() error {
	// Blockchain validation
	if c.Blockchain.Difficulty == 0 || c.Blockchain.Difficulty > 8 {
		return fmt.Errorf("blockchain difficulty must be between 1 and 8")
	}

	if c.Blockchain.MiningReward < 0 {
		return fmt.Errorf("mining reward cannot be negative")
	}

	// Device validation
	if c.Device.DeviceTimeoutSeconds < 10 {
		return fmt.Errorf("device timeout must be at least 10 seconds")
	}

	// API validation
	if c.API.Enabled {
		if c.API.Port < 1 || c.API.Port > 65535 {
			return fmt.Errorf("API port must be between 1 and 65535")
		}

		if c.API.AuthEnabled && c.API.JWTSecret == "" {
			return fmt.Errorf("JWT secret must be provided when API authentication is enabled")
		}
	}

	// MQTT validation
	if c.MQTT.Enabled {
		if c.MQTT.Broker == "" {
			return fmt.Errorf("MQTT broker address must be provided when MQTT is enabled")
		}

		if c.MQTT.Port < 1 || c.MQTT.Port > 65535 {
			return fmt.Errorf("MQTT port must be between 1 and 65535")
		}
	}

	// Web validation
	if c.Web.Enabled {
		if c.Web.Port < 1 || c.Web.Port > 65535 {
			return fmt.Errorf("Web port must be between 1 and 65535")
		}
	}

	return nil
}

// SaveConfig saves the configuration to a file
func (c *Config) SaveConfig(path string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("error creating directory: %w", err)
	}

	// Determine file type by extension
	ext := strings.ToLower(filepath.Ext(path))

	var data []byte
	var err error

	switch ext {
	case ".json":
		data, err = json.MarshalIndent(c, "", "  ")
		if err != nil {
			return fmt.Errorf("error marshaling config to JSON: %w", err)
		}
	case ".yaml", ".yml":
		data, err = yaml.Marshal(c)
		if err != nil {
			return fmt.Errorf("error marshaling config to YAML: %w", err)
		}
	default:
		return fmt.Errorf("unsupported config file format: %s", ext)
	}

	// Write to file
	if err := ioutil.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("error writing config file: %w", err)
	}

	return nil
}

// LoadOrCreateConfig loads a config or creates a default one if it doesn't exist
func LoadOrCreateConfig(path string) (*Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Config doesn't exist, create default
		config := DefaultConfig()
		if err := config.SaveConfig(path); err != nil {
			return nil, fmt.Errorf("error creating default config: %w", err)
		}
		return config, nil
	}

	// Config exists, load it
	return LoadConfig(path)
}

// generateDefaultSecret creates a simple random secret for development
// In production, this should be provided by the user
func generateDefaultSecret() string {
	// This is just a placeholder - in a real app, use crypto/rand
	return "change-me-in-production-eb0e1c34a20fd77b"
}
