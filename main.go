// IOTSIM is a simple IoT authentication simulator that demonstrates the BasIoT protocol.
// The simulator creates a blockchain system with devices and resources, and simulates different scenarios for authentication.
// The scenarios include legitimate authentication, hacker attempts, expired requests, and replay attacks.
// Made for seminar by exprays a.k.a surya

package main

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	rn "math/rand"
	"os"
	"strings"
	"time"
)

const (
	ASCII_BANNER = `
[1;36m╔══════════════════════════════════════════╗
║                 IOTSIM                   ║
║          Secure IoT Auth Demo            ║
║                                          ║
║            made by exprays              ║
╚══════════════════════════════════════════╝[0m
`
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
)

// Device represents an IoT device
type Device struct {
	ID         string          `json:"device_identifier"`
	Descriptor string          `json:"device_descriptor"`
	Address    string          `json:"d_addr"`
	PrivateKey *rsa.PrivateKey `json:"-"`
	PublicKey  *rsa.PublicKey  `json:"-"`
}

// ResourceHolder represents a resource provider in the IoT network
type ResourceHolder struct {
	ID         string          `json:"resource_id"`
	Type       string          `json:"resource_type"`
	PrivateKey *rsa.PrivateKey `json:"-"`
	PublicKey  *rsa.PublicKey  `json:"-"`
}

// AuthRequest represents an authentication request
type AuthRequest struct {
	DeviceAddr string    `json:"device_addr"`
	ResourceID string    `json:"resource_id"`
	Timestamp  time.Time `json:"timestamp"`
	Nonce      string    `json:"nonce"`
	Signature  string    `json:"signature"`
}

// SimulationType represents different simulation scenarios
type SimulationType int

const (
	LegitimateAuth SimulationType = iota
	HackerAttempt
	ExpiredRequest
	ReplayAttack
)

func (st SimulationType) String() string {
	return [...]string{
		"Legitimate Authentication",
		"Hacker Attempt",
		"Expired Request",
		"Replay Attack",
	}[st]
}

// BlockchainSimulator simulates a basic blockchain for device registry
type BlockchainSimulator struct {
	Devices   map[string]*Device
	Resources map[string]*ResourceHolder
}

// NewBlockchainSimulator creates a new blockchain simulator
func NewBlockchainSimulator() *BlockchainSimulator {
	return &BlockchainSimulator{
		Devices:   make(map[string]*Device),
		Resources: make(map[string]*ResourceHolder),
	}
}

func (bc *BlockchainSimulator) RegisterDevice(device *Device) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %v", err)
	}

	device.PrivateKey = privateKey
	device.PublicKey = &privateKey.PublicKey

	addr := make([]byte, 32)
	rand.Read(addr)
	device.Address = base64.StdEncoding.EncodeToString(addr)

	bc.Devices[device.ID] = device
	return nil
}

func (bc *BlockchainSimulator) RegisterResource(resource *ResourceHolder) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %v", err)
	}

	resource.PrivateKey = privateKey
	resource.PublicKey = &privateKey.PublicKey

	bc.Resources[resource.ID] = resource
	return nil
}

// AuthenticationProtocol implements the BasIoT authentication process
type AuthenticationProtocol struct {
	blockchain   *BlockchainSimulator
	usedNonces   map[string]bool
	replayWindow time.Duration
	nonceCleanup time.Time
}

func NewAuthenticationProtocol(bc *BlockchainSimulator) *AuthenticationProtocol {
	return &AuthenticationProtocol{
		blockchain:   bc,
		usedNonces:   make(map[string]bool),
		replayWindow: 5 * time.Minute,
		nonceCleanup: time.Now(),
	}
}

func (ap *AuthenticationProtocol) recordNonce(nonce string) {
	ap.usedNonces[nonce] = true
}

func (ap *AuthenticationProtocol) isNonceUsed(nonce string) bool {
	if time.Since(ap.nonceCleanup) > time.Hour {
		ap.cleanupNonces()
	}
	return ap.usedNonces[nonce]
}

func (ap *AuthenticationProtocol) cleanupNonces() {
	ap.usedNonces = make(map[string]bool)
	ap.nonceCleanup = time.Now()
}

func (ap *AuthenticationProtocol) RequestAuthentication(deviceID, resourceID string) (*AuthRequest, error) {
	device, exists := ap.blockchain.Devices[deviceID]
	if !exists {
		return nil, fmt.Errorf("device not found: %s", deviceID)
	}

	if _, exists := ap.blockchain.Resources[resourceID]; !exists {
		return nil, fmt.Errorf("resource not found: %s", resourceID)
	}

	nonce := make([]byte, 32)
	rand.Read(nonce)
	nonceStr := base64.StdEncoding.EncodeToString(nonce)

	request := &AuthRequest{
		DeviceAddr: device.Address,
		ResourceID: resourceID,
		Timestamp:  time.Now(),
		Nonce:      nonceStr,
	}

	message := fmt.Sprintf("%s%s%s%s", request.DeviceAddr, request.ResourceID,
		request.Timestamp.Format(time.RFC3339), request.Nonce)
	hashed := sha256.Sum256([]byte(message))

	signature, err := rsa.SignPKCS1v15(rand.Reader, device.PrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign request: %v", err)
	}

	request.Signature = base64.StdEncoding.EncodeToString(signature)
	return request, nil
}

func (ap *AuthenticationProtocol) SimulateHackerAttempt(request *AuthRequest) *AuthRequest {
	hackedRequest := *request
	switch rn.Intn(3) {
	case 0:
		hackedRequest.DeviceAddr = "hacked_" + hackedRequest.DeviceAddr
	case 1:
		hackedRequest.Timestamp = hackedRequest.Timestamp.Add(time.Hour)
	case 2:
		sig := []byte(hackedRequest.Signature)
		sig[len(sig)-1] ^= 1
		hackedRequest.Signature = string(sig)
	}
	return &hackedRequest
}

func (ap *AuthenticationProtocol) SimulateScenario(request *AuthRequest, simType SimulationType) *AuthRequest {
	switch simType {
	case HackerAttempt:
		return ap.SimulateHackerAttempt(request)
	case ExpiredRequest:
		modifiedRequest := *request
		modifiedRequest.Timestamp = time.Now().Add(-10 * time.Minute)
		return &modifiedRequest
	case ReplayAttack:
		ap.recordNonce(request.Nonce)
		return request
	default:
		return request
	}
}

func (ap *AuthenticationProtocol) VerifyAuthentication(request *AuthRequest) (bool, error) {
	if time.Since(request.Timestamp) > 5*time.Minute {
		return false, fmt.Errorf("request expired: timestamp too old")
	}

	if ap.isNonceUsed(request.Nonce) {
		return false, fmt.Errorf("nonce already used: possible replay attack")
	}

	var device *Device
	for _, d := range ap.blockchain.Devices {
		if d.Address == request.DeviceAddr {
			device = d
			break
		}
	}

	if device == nil {
		return false, fmt.Errorf("device not found with address: %s", request.DeviceAddr)
	}

	message := fmt.Sprintf("%s%s%s%s", request.DeviceAddr, request.ResourceID,
		request.Timestamp.Format(time.RFC3339), request.Nonce)
	hashed := sha256.Sum256([]byte(message))

	signature, err := base64.StdEncoding.DecodeString(request.Signature)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %v", err)
	}

	err = rsa.VerifyPKCS1v15(device.PublicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return false, nil
	}

	ap.recordNonce(request.Nonce)
	return true, nil
}

func printColored(color, message string) {
	fmt.Printf("%s%s%s\n", color, message, ColorReset)
}

func getUserInput(prompt string) string {
	printColored(ColorYellow, prompt)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func printResult(success bool, message string) {
	if success {
		printColored(ColorGreen, "✓ SUCCESS: "+message)
	} else {
		printColored(ColorRed, "✗ FAILURE: "+message)
	}
}

func printDivider() {
	printColored(ColorCyan, strings.Repeat("=", 50))
}

func printHeader(title string) {
	printDivider()
	printColored(ColorPurple, title)
	printDivider()
}

func colorBool(b bool) string {
	if b {
		return ColorGreen + "✓" + ColorReset
	}
	return ColorRed + "✗" + ColorReset
}

func main() {
	fmt.Println(ASCII_BANNER)

	blockchain := NewBlockchainSimulator()

	device := &Device{
		ID:         "device001",
		Descriptor: "Temperature Sensor",
	}
	resource := &ResourceHolder{
		ID:   "resource001",
		Type: "Data Storage",
	}

	if err := blockchain.RegisterDevice(device); err != nil {
		log.Fatalf("Failed to register device: %v", err)
	}
	if err := blockchain.RegisterResource(resource); err != nil {
		log.Fatalf("Failed to register resource: %v", err)
	}

	auth := NewAuthenticationProtocol(blockchain)

	printColored(ColorGreen, "Blockchain System Initialized Successfully!")
	printColored(ColorGreen, "Device and Resource Registered!")

	for {
		printColored(ColorYellow, "\nAvailable Simulation Scenarios:")
		printColored(ColorCyan, "1. Legitimate Authentication")
		printColored(ColorCyan, "2. Hacker Attempt")
		printColored(ColorCyan, "3. Expired Request")
		printColored(ColorCyan, "4. Replay Attack")
		printColored(ColorCyan, "5. Exit")

		choice := getUserInput("\nSelect scenario (1-5): ")

		if choice == "5" {
			printColored(ColorGreen, "Exiting simulator. Goodbye!")
			break
		}

		var simType SimulationType
		switch choice {
		case "1":
			simType = LegitimateAuth
		case "2":
			simType = HackerAttempt
		case "3":
			simType = ExpiredRequest
		case "4":
			simType = ReplayAttack
		default:
			printColored(ColorRed, "Invalid choice. Please try again.")
			continue
		}

		printHeader(fmt.Sprintf("Simulating: %s", simType))

		request, err := auth.RequestAuthentication(device.ID, resource.ID)
		if err != nil {
			printColored(ColorRed, fmt.Sprintf("Error creating request: %v", err))
			continue
		}

		simulatedRequest := auth.SimulateScenario(request, simType)
		requestJSON, _ := json.MarshalIndent(simulatedRequest, "", "  ")

		printColored(ColorBlue, "Authentication Request:")
		fmt.Println(string(requestJSON))

		verified, err := auth.VerifyAuthentication(simulatedRequest)

		if verified {
			printResult(true, "Authentication successful")
		} else {
			if err != nil {
				printResult(false, fmt.Sprintf("Authentication failed: %v", err))
			} else {
				printResult(false, "Authentication failed: Invalid signature")
			}
		}

		printHeader("Security Analysis")
		printColored(ColorCyan, "Checks Performed:")
		fmt.Printf("• Signature Verification: %s\n", colorBool(verified))
		fmt.Printf("• Timestamp Valid: %s\n", colorBool(time.Since(simulatedRequest.Timestamp) <= 5*time.Minute))
		fmt.Printf("• Nonce Unique: %s\n", colorBool(!auth.isNonceUsed(simulatedRequest.Nonce)))
		fmt.Printf("• Device Verified: %s\n", colorBool(device.Address == simulatedRequest.DeviceAddr))
	}
}
