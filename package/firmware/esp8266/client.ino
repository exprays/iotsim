#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <WiFiClient.h>
#include <ArduinoJson.h>
#include <PubSubClient.h>
#include <Ticker.h>

// Device Configuration
const char* DEVICE_NAME = "ESP8266_NODE_1"; // Change to NODE_2 for second device
const char* WIFI_SSID = "YourWiFiSSID";
const char* WIFI_PASSWORD = "YourWiFiPassword";

// IoT Blockchain Toolkit Configuration
const char* API_HOST = "192.168.1.100"; // Change to your server IP
const int API_PORT = 8080;
const char* MQTT_BROKER = "192.168.1.100"; // Change to your MQTT broker IP
const int MQTT_PORT = 1883;

// Device Pins
const int LED_PIN = D2;  // GPIO4
const int BUTTON_PIN = D5; // GPIO14

// Device State
String deviceId = "";
String apiKey = "";
bool ledState = false;
float temperatureValue = 0.0;
unsigned long lastUpdateTime = 0;
unsigned long updateInterval = 30000; // 30 seconds
int buttonState = 0;
int lastButtonState = 0;
unsigned long lastDebounceTime = 0;
unsigned long debounceDelay = 50;

// MQTT Client
WiFiClient espClient;
PubSubClient mqttClient(espClient);

// Ticker for simulating sensor readings
Ticker sensorTicker;

void setup() {
  // Initialize serial
  Serial.begin(115200);
  Serial.println("\n\nStarting IoT Blockchain Client");
  
  // Initialize pins
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  
  // Connect to WiFi
  connectToWiFi();
  
  // Register device with blockchain toolkit
  registerDevice();
  
  // Set up MQTT
  setupMQTT();
  
  // Start sensor simulation
  sensorTicker.attach(10, simulateSensorReading);
  
  Serial.println("Setup completed");
}

void loop() {
  // Handle WiFi connection
  if (WiFi.status() != WL_CONNECTED) {
    connectToWiFi();
    return;
  }
  
  // Handle MQTT connection
  if (!mqttClient.connected()) {
    reconnectMQTT();
  }
  mqttClient.loop();
  
  // Read button state (debounced)
  int reading = digitalRead(BUTTON_PIN);
  if (reading != lastButtonState) {
    lastDebounceTime = millis();
  }
  
  if ((millis() - lastDebounceTime) > debounceDelay) {
    if (reading != buttonState) {
      buttonState = reading;
      if (buttonState == LOW) { // Button pressed
        // Toggle LED
        ledState = !ledState;
        digitalWrite(LED_PIN, ledState);
        
        // Report state change
        reportLEDState();
      }
    }
  }
  lastButtonState = reading;
  
  // Send periodic updates
  if (millis() - lastUpdateTime > updateInterval) {
    sendSensorData();
    lastUpdateTime = millis();
  }
}

void connectToWiFi() {
  Serial.printf("\nConnecting to %s ", WIFI_SSID);
  
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  
  int connectionAttempts = 0;
  while (WiFi.status() != WL_CONNECTED && connectionAttempts < 20) {
    delay(500);
    Serial.print(".");
    connectionAttempts++;
  }
  
  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("\nWiFi connected, IP address: %s\n", WiFi.localIP().toString().c_str());
  } else {
    Serial.println("\nFailed to connect to WiFi. Retrying in 5 seconds...");
    delay(5000);
  }
}

void registerDevice() {
  if (WiFi.status() != WL_CONNECTED) {
    return;
  }
  
  Serial.println("Registering device with IoT Blockchain Toolkit...");
  
  WiFiClient client;
  HTTPClient http;
  
  // Format the URL
  String url = "http://" + String(API_HOST) + ":" + String(API_PORT) + "/api/esp8266";
  
  // Start the HTTP request
  http.begin(client, url);
  http.addHeader("Content-Type", "application/json");
  
  // Prepare the request body
  StaticJsonDocument<256> jsonDoc;
  jsonDoc["name"] = DEVICE_NAME;
  jsonDoc["wifiSsid"] = WIFI_SSID;
  
  String requestBody;
  serializeJson(jsonDoc, requestBody);
  
  // Send the request
  int httpResponseCode = http.POST(requestBody);
  
  if (httpResponseCode == 201) { // Created
    String response = http.getString();
    
    // Parse the response
    StaticJsonDocument<512> responseDoc;
    DeserializationError error = deserializeJson(responseDoc, response);
    
    if (!error) {
      deviceId = responseDoc["id"].as<String>();
      apiKey = responseDoc["metadata"]["api_key"].as<String>();
      
      Serial.println("Device registered successfully!");
      Serial.print("Device ID: ");
      Serial.println(deviceId);
      Serial.print("API Key: ");
      Serial.println(apiKey);
    } else {
      Serial.println("Error parsing registration response");
    }
  } else {
    Serial.print("Registration failed, HTTP response code: ");
    Serial.println(httpResponseCode);
    String response = http.getString();
    Serial.println(response);
  }
  
  http.end();
}

void setupMQTT() {
  mqttClient.setServer(MQTT_BROKER, MQTT_PORT);
  mqttClient.setCallback(mqttCallback);
  reconnectMQTT();
}

void reconnectMQTT() {
  if (deviceId == "") {
    return; // Can't connect without device ID
  }
  
  // Loop until connected
  while (!mqttClient.connected() && WiFi.status() == WL_CONNECTED) {
    Serial.print("Connecting to MQTT broker...");
    
    // Create a client ID based on device ID
    String clientId = "ESP8266-" + deviceId.substring(0, 8);
    
    // Attempt to connect
    if (mqttClient.connect(clientId.c_str())) {
      Serial.println("connected");
      
      // Subscribe to device-specific topics
      String commandTopic = "iot-blockchain/device/" + deviceId + "/command";
      mqttClient.subscribe(commandTopic.c_str());
      
      // Announce presence
      String statusTopic = "iot-blockchain/device/" + deviceId + "/status";
      mqttClient.publish(statusTopic.c_str(), "online", true);
    } else {
      Serial.print("failed, rc=");
      Serial.print(mqttClient.state());
      Serial.println(" try again in 5 seconds");
      delay(5000);
    }
  }
}

void mqttCallback(char* topic, byte* payload, unsigned int length) {
  // Convert payload to string
  char message[length + 1];
  memcpy(message, payload, length);
  message[length] = '\0';
  
  Serial.print("Message arrived on topic: ");
  Serial.print(topic);
  Serial.print(", message: ");
  Serial.println(message);
  
  // Parse JSON command
  StaticJsonDocument<256> jsonDoc;
  DeserializationError error = deserializeJson(jsonDoc, message);
  
  if (!error) {
    String command = jsonDoc["command"].as<String>();
    
    // Handle LED command
    if (command == "set_led") {
      bool newState = jsonDoc["params"]["state"].as<bool>();
      ledState = newState;
      digitalWrite(LED_PIN, ledState);
      
      // Confirm the state change
      reportLEDState();
    }
  }
}

void reportLEDState() {
  // Only proceed if we have a device ID
  if (deviceId == "") return;
  
  // Publish to MQTT
  if (mqttClient.connected()) {
    String statusTopic = "iot-blockchain/device/" + deviceId + "/led";
    String payload = ledState ? "on" : "off";
    mqttClient.publish(statusTopic.c_str(), payload.c_str());
  }
  
  // Submit to blockchain via HTTP
  String url = "http://" + String(API_HOST) + ":" + String(API_PORT) + "/device-api/sensors/led";
  
  WiFiClient client;
  HTTPClient http;
  
  http.begin(client, url);
  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-API-Key", apiKey);
  
  StaticJsonDocument<128> jsonDoc;
  jsonDoc["value"] = ledState ? 1.0 : 0.0;
  
  String requestBody;
  serializeJson(jsonDoc, requestBody);
  
  int httpResponseCode = http.POST(requestBody);
  
  if (httpResponseCode == 200) {
    Serial.println("LED state recorded on blockchain");
  } else {
    Serial.print("Failed to record LED state, HTTP code: ");
    Serial.println(httpResponseCode);
  }
  
  http.end();
}

void simulateSensorReading() {
  // Simulate temperature reading with some random variation
  temperatureValue = 22.0 + ((float)random(0, 100) / 50.0); // 21-23°C range
}

void sendSensorData() {
  // Only proceed if we have a device ID
  if (deviceId == "") return;
  
  // Submit to blockchain via HTTP
  String url = "http://" + String(API_HOST) + ":" + String(API_PORT) + "/device-api/sensors/temperature";
  
  WiFiClient client;
  HTTPClient http;
  
  http.begin(client, url);
  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-API-Key", apiKey);
  
  StaticJsonDocument<128> jsonDoc;
  jsonDoc["value"] = temperatureValue;
  
  String requestBody;
  serializeJson(jsonDoc, requestBody);
  
  int httpResponseCode = http.POST(requestBody);
  
  if (httpResponseCode == 200) {
    Serial.printf("Temperature (%.2f°C) recorded on blockchain\n", temperatureValue);
  } else {
    Serial.print("Failed to record temperature, HTTP code: ");
    Serial.println(httpResponseCode);
  }
  
  http.end();
}