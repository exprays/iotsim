package mqtt

// Config represents MQTT client configuration
type Config struct {
	Enabled      bool   `json:"enabled" yaml:"enabled"`
	Broker       string `json:"broker" yaml:"broker"`
	Port         int    `json:"port" yaml:"port"`
	ClientID     string `json:"clientId" yaml:"clientId"`
	Username     string `json:"username" yaml:"username"`
	Password     string `json:"password" yaml:"password"`
	TopicRoot    string `json:"topicRoot" yaml:"topicRoot"`
	QoS          int    `json:"qos" yaml:"qos"`
	KeepAlive    int    `json:"keepAlive" yaml:"keepAlive"`
	CleanSession bool   `json:"cleanSession" yaml:"cleanSession"`
	Timeout      int    `json:"timeout" yaml:"timeout"`
}

// DefaultConfig returns the default MQTT configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled:      true,
		Broker:       "localhost",
		Port:         1883,
		ClientID:     "iot-blockchain-toolkit",
		Username:     "",
		Password:     "",
		TopicRoot:    "iot-blockchain",
		QoS:          1,
		KeepAlive:    30,
		CleanSession: true,
		Timeout:      30,
	}
}
