package main

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// MonitorData represents the data structure sent to the dashboard
type MonitorData struct {
	Devices     []*Device       `json:"devices"`
	AuthMetrics AuthMetrics     `json:"authMetrics"`
	Events      []SecurityEvent `json:"events"`
}

type AuthMetrics struct {
	LegitimateAuth  int `json:"legitimateAuth"`
	HackerAttempts  int `json:"hackerAttempts"`
	ExpiredRequests int `json:"expiredRequests"`
	ReplayAttacks   int `json:"replayAttacks"`
}

type SecurityEvent struct {
	Timestamp time.Time      `json:"timestamp"`
	Type      SimulationType `json:"type"`
	DeviceID  string         `json:"deviceId"`
	Success   bool           `json:"success"`
}

type Monitor struct {
	blockchain *BlockchainSimulator
	auth       *AuthenticationProtocol
	clients    map[*websocket.Conn]bool
	broadcast  chan MonitorData
	mutex      sync.Mutex
	metrics    AuthMetrics
	events     []SecurityEvent
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for demo
	},
}

func NewMonitor(bc *BlockchainSimulator, auth *AuthenticationProtocol) *Monitor {
	return &Monitor{
		blockchain: bc,
		auth:       auth,
		clients:    make(map[*websocket.Conn]bool),
		broadcast:  make(chan MonitorData),
		events:     make([]SecurityEvent, 0),
	}
}

func (m *Monitor) handleConnections(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Error upgrading connection: %v", err)
		return
	}
	defer ws.Close()

	m.mutex.Lock()
	m.clients[ws] = true
	m.mutex.Unlock()

	// Send initial data
	devices := make([]*Device, 0)
	for _, device := range m.blockchain.Devices {
		devices = append(devices, device)
	}

	initialData := MonitorData{
		Devices:     devices,
		AuthMetrics: m.metrics,
		Events:      m.events,
	}

	err = ws.WriteJSON(initialData)
	if err != nil {
		log.Printf("Error sending initial data: %v", err)
		return
	}

	// Keep connection alive and handle disconnection
	for {
		_, _, err := ws.ReadMessage()
		if err != nil {
			m.mutex.Lock()
			delete(m.clients, ws)
			m.mutex.Unlock()
			break
		}
	}
}

func (m *Monitor) RecordAuthEvent(simType SimulationType, deviceID string, success bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	event := SecurityEvent{
		Timestamp: time.Now(),
		Type:      simType,
		DeviceID:  deviceID,
		Success:   success,
	}

	// Update metrics
	switch simType {
	case LegitimateAuth:
		if success {
			m.metrics.LegitimateAuth++
		}
	case HackerAttempt:
		m.metrics.HackerAttempts++
	case ExpiredRequest:
		m.metrics.ExpiredRequests++
	case ReplayAttack:
		m.metrics.ReplayAttacks++
	}

	// Keep last 100 events
	m.events = append(m.events, event)
	if len(m.events) > 100 {
		m.events = m.events[1:]
	}

	// Broadcast update
	m.broadcastUpdate()
}

func (m *Monitor) broadcastUpdate() {
	devices := make([]*Device, 0)
	for _, device := range m.blockchain.Devices {
		devices = append(devices, device)
	}

	data := MonitorData{
		Devices:     devices,
		AuthMetrics: m.metrics,
		Events:      m.events,
	}

	for client := range m.clients {
		err := client.WriteJSON(data)
		if err != nil {
			log.Printf("Error broadcasting to client: %v", err)
			client.Close()
			delete(m.clients, client)
		}
	}
}

func (m *Monitor) StartServer() {
	http.HandleFunc("/ws", m.handleConnections)
	go func() {
		log.Println("Starting WebSocket server on :8080")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatal("Error starting server:", err)
		}
	}()
}
