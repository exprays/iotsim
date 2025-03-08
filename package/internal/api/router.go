package api

import (
	"fmt"
	"net/http"

	"ranger/internal/core"

	"github.com/gorilla/mux"
)

// Router represents the API router with all routes configured
type Router struct {
	*mux.Router
	app    *core.App
	config *core.APIConfig
}

// SetupRouter creates and configures the API router with all routes and middleware
func SetupRouter(app *core.App, jwtSecret string, allowedOrigins []string) http.Handler {
	// Create a new router instance
	router := NewRouter(app)

	// Configure additional settings based on parameters if needed
	if jwtSecret != "" && jwtSecret != router.config.JWTSecret {
		// Update JWT secret if different from config
		router.config.JWTSecret = jwtSecret
	}

	if len(allowedOrigins) > 0 {
		// Update allowed origins if provided
		router.config.AllowedOrigins = allowedOrigins
	}

	return router
}

// NewRouter creates a new API router with all routes configured
func NewRouter(app *core.App) *Router {
	r := &Router{
		Router: mux.NewRouter(),
		app:    app,
		config: &app.Config.API,
	}

	// Set up routes
	r.setupRoutes()

	return r
}

// setupRoutes configures all API routes
func (r *Router) setupRoutes() {
	// API version prefix
	api := r.PathPrefix("/api/v1").Subrouter()

	// Public routes (no authentication required)
	public := api.NewRoute().Subrouter()
	public.Use(r.LoggingMiddleware)
	public.Use(r.CORSMiddleware)

	public.HandleFunc("/health", r.HealthCheckHandler).Methods("GET")
	public.HandleFunc("/login", r.LoginHandler).Methods("POST")

	// Protected routes (authentication required)
	protected := api.NewRoute().Subrouter()
	protected.Use(r.LoggingMiddleware)
	protected.Use(r.CORSMiddleware)

	// Only add authentication middleware if enabled in config
	if r.config.AuthEnabled {
		protected.Use(r.AuthMiddleware)
	}

	// System routes
	protected.HandleFunc("/system/status", r.SystemStatusHandler).Methods("GET")
	protected.HandleFunc("/system/metrics", r.SystemMetricsHandler).Methods("GET")

	// Blockchain routes
	protected.HandleFunc("/blockchain/status", r.BlockchainStatusHandler).Methods("GET")
	protected.HandleFunc("/blockchain/blocks", r.GetBlocksHandler).Methods("GET")
	protected.HandleFunc("/blockchain/blocks/{hash}", r.GetBlockByHashHandler).Methods("GET")
	protected.HandleFunc("/blockchain/transactions", r.GetTransactionsHandler).Methods("GET")
	protected.HandleFunc("/blockchain/transactions/{id}", r.GetTransactionByIDHandler).Methods("GET")
	protected.HandleFunc("/blockchain/mine", r.MineBlockHandler).Methods("POST")
	protected.HandleFunc("/blockchain/validate", r.ValidateBlockchainHandler).Methods("GET")

	// Device routes
	r.Router.HandleFunc("/api/devices", r.ListDevicesHandler).Methods("GET")
	r.Router.HandleFunc("/api/devices", r.RegisterDeviceHandler).Methods("POST")
	protected.HandleFunc("/devices/{id}", r.GetDeviceHandler).Methods("GET")
	protected.HandleFunc("/devices/{id}", r.UpdateDeviceHandler).Methods("PUT")
	protected.HandleFunc("/devices/{id}", r.DeleteDeviceHandler).Methods("DELETE")
	protected.HandleFunc("/devices/{id}/status", r.UpdateDeviceStatusHandler).Methods("PUT")
	protected.HandleFunc("/devices/{id}/data", r.GetDeviceDataHandler).Methods("GET")
	protected.HandleFunc("/devices/{id}/command", r.SendDeviceCommandHandler).Methods("POST")

	// ESP8266 specific routes
	r.Router.HandleFunc("/api/esp8266", r.ListESP8266Handler).Methods("GET")
	r.Router.HandleFunc("/api/esp8266", r.RegisterESP8266Handler).Methods("POST")
	protected.HandleFunc("/esp8266/{id}/led", r.UpdateESP8266LEDHandler).Methods("PUT")
	protected.HandleFunc("/esp8266/{id}/readings", r.GetESP8266ReadingsHandler).Methods("GET")

	// Documentation route
	api.HandleFunc("/docs", r.APIDocsHandler).Methods("GET")

	// 404 handler for unmatched routes
	r.Router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Resource not found"))
	})
}

// APIDocsHandler handles requests for API documentation
func (r *Router) APIDocsHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("<h1>API Documentation</h1><p>Documentation for the API endpoints.</p>"))
}

// UpdateESP8266LEDHandler handles requests to update the LED status of an ESP8266 device
func (r *Router) UpdateESP8266LEDHandler(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id := vars["id"]

	// In a real implementation, you would parse the request body and update the LED status
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"message":"LED status updated for device %s"}`, id)))
}

// GetESP8266ReadingsHandler handles requests to retrieve sensor readings from an ESP8266 device
func (r *Router) GetESP8266ReadingsHandler(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id := vars["id"]

	// In a real implementation, you would fetch readings from the device or database
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"device":"%s","temperature":22.5,"humidity":48.2}`, id)))
}

// ListESP8266Handler handles requests to list all ESP8266 devices
func (r *Router) ListESP8266Handler(w http.ResponseWriter, req *http.Request) {
	// In a real implementation, you would fetch the list of ESP8266 devices from your database
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"devices":[{"id":"esp-001","status":"online"},{"id":"esp-002","status":"offline"}]}`))
}

// StartServer starts the API server
func (r *Router) StartServer() error {
	addr := fmt.Sprintf("%s:%d", r.config.Host, r.config.Port)
	fmt.Printf("Starting API server at %s\n", addr)
	return http.ListenAndServe(addr, r)
}
