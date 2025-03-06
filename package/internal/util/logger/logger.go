package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

// LogLevel represents logging severity levels
type LogLevel string

// Log levels
const (
	DebugLevel LogLevel = "debug"
	InfoLevel  LogLevel = "info"
	WarnLevel  LogLevel = "warn"
	ErrorLevel LogLevel = "error"
	FatalLevel LogLevel = "fatal"
)

// Config holds logger configuration
type Config struct {
	Level            LogLevel `json:"level" yaml:"level"`
	Format           string   `json:"format" yaml:"format"` // console or json
	EnableConsole    bool     `json:"enableConsole" yaml:"enableConsole"`
	ConsoleLevel     LogLevel `json:"consoleLevel" yaml:"consoleLevel"`
	EnableFile       bool     `json:"enableFile" yaml:"enableFile"`
	FileLevel        LogLevel `json:"fileLevel" yaml:"fileLevel"`
	FilePath         string   `json:"filePath" yaml:"filePath"`
	FileMaxSize      int      `json:"fileMaxSize" yaml:"fileMaxSize"`           // MB
	FileMaxBackups   int      `json:"fileMaxBackups" yaml:"fileMaxBackups"`     // number of files
	FileMaxAge       int      `json:"fileMaxAge" yaml:"fileMaxAge"`             // days
	FileCompress     bool     `json:"fileCompress" yaml:"fileCompress"`         // compress rotated files
	DeviceIDField    string   `json:"deviceIdField" yaml:"deviceIdField"`       // field name for device ID
	TransactionField string   `json:"transactionField" yaml:"transactionField"` // field name for transaction ID
}

// Logger is the main logger for the application
type Logger struct {
	zap           *zap.Logger
	sugar         *zap.SugaredLogger
	level         zap.AtomicLevel
	config        *Config
	fields        map[string]interface{}
	fieldsMutex   sync.RWMutex
	defaultFields []zap.Field
}

// DefaultConfig returns a default logger configuration
func DefaultConfig() *Config {
	return &Config{
		Level:            InfoLevel,
		Format:           "console",
		EnableConsole:    true,
		ConsoleLevel:     InfoLevel,
		EnableFile:       true,
		FileLevel:        DebugLevel,
		FilePath:         "./logs/iot-blockchain.log",
		FileMaxSize:      100,
		FileMaxBackups:   5,
		FileMaxAge:       30,
		FileCompress:     true,
		DeviceIDField:    "device_id",
		TransactionField: "tx_id",
	}
}

var (
	defaultLogger *Logger
	once          sync.Once
)

// New creates a new logger with the given configuration
func New(config *Config) (*Logger, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Set up log level
	level := getZapLevel(config.Level)
	atomicLevel := zap.NewAtomicLevelAt(level)

	// Create encoder config
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "message",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	// Create cores
	var cores []zapcore.Core

	// Console output core
	if config.EnableConsole {
		var encoder zapcore.Encoder
		if config.Format == "json" {
			encoder = zapcore.NewJSONEncoder(encoderConfig)
		} else {
			encoder = zapcore.NewConsoleEncoder(encoderConfig)
		}
		consoleLevel := getZapLevel(config.ConsoleLevel)
		consoleCore := zapcore.NewCore(encoder, zapcore.AddSync(os.Stdout), zap.NewAtomicLevelAt(consoleLevel))
		cores = append(cores, consoleCore)
	}

	// File output core
	if config.EnableFile {
		// Ensure directory exists
		if err := os.MkdirAll(filepath.Dir(config.FilePath), 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}

		// Set up log rotation
		fileWriter := zapcore.AddSync(&lumberjack.Logger{
			Filename:   config.FilePath,
			MaxSize:    config.FileMaxSize,
			MaxBackups: config.FileMaxBackups,
			MaxAge:     config.FileMaxAge,
			Compress:   config.FileCompress,
		})

		var encoder zapcore.Encoder
		if config.Format == "json" {
			encoder = zapcore.NewJSONEncoder(encoderConfig)
		} else {
			encoder = zapcore.NewConsoleEncoder(encoderConfig)
		}

		fileLevel := getZapLevel(config.FileLevel)
		fileCore := zapcore.NewCore(encoder, fileWriter, zap.NewAtomicLevelAt(fileLevel))
		cores = append(cores, fileCore)
	}

	// Combine cores
	core := zapcore.NewTee(cores...)

	// Create logger
	zapLogger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))

	return &Logger{
		zap:           zapLogger,
		sugar:         zapLogger.Sugar(),
		level:         atomicLevel,
		config:        config,
		fields:        make(map[string]interface{}),
		defaultFields: []zap.Field{},
	}, nil
}

// GetDefaultLogger returns the singleton default logger
func GetDefaultLogger() *Logger {
	once.Do(func() {
		logger, err := New(DefaultConfig())
		if err != nil {
			// If we can't create a logger, create one that only logs to console
			fmt.Printf("Failed to create default logger: %v, using console-only logger\n", err)
			consoleOnlyConfig := DefaultConfig()
			consoleOnlyConfig.EnableFile = false
			logger, _ = New(consoleOnlyConfig)
		}
		defaultLogger = logger
	})
	return defaultLogger
}

// SetDefaultLogger sets the default logger
func SetDefaultLogger(logger *Logger) {
	defaultLogger = logger
}

// WithField adds a field to the logger
func (l *Logger) WithField(key string, value interface{}) *Logger {
	l.fieldsMutex.Lock()
	defer l.fieldsMutex.Unlock()

	newLogger := &Logger{
		zap:           l.zap,
		sugar:         l.sugar,
		level:         l.level,
		config:        l.config,
		fields:        make(map[string]interface{}),
		defaultFields: l.defaultFields,
	}

	// Copy existing fields
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}

	// Add new field
	newLogger.fields[key] = value

	// Convert fields to zap fields
	fields := make([]zap.Field, 0, len(newLogger.fields))
	for k, v := range newLogger.fields {
		fields = append(fields, zap.Any(k, v))
	}
	newLogger.defaultFields = fields

	return newLogger
}

// WithFields adds multiple fields to the logger
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	l.fieldsMutex.Lock()
	defer l.fieldsMutex.Unlock()

	newLogger := &Logger{
		zap:           l.zap,
		sugar:         l.sugar,
		level:         l.level,
		config:        l.config,
		fields:        make(map[string]interface{}),
		defaultFields: l.defaultFields,
	}

	// Copy existing fields
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}

	// Add new fields
	for k, v := range fields {
		newLogger.fields[k] = v
	}

	// Convert fields to zap fields
	zapFields := make([]zap.Field, 0, len(newLogger.fields))
	for k, v := range newLogger.fields {
		zapFields = append(zapFields, zap.Any(k, v))
	}
	newLogger.defaultFields = zapFields

	return newLogger
}

// WithDeviceID adds a device ID field to the logger
func (l *Logger) WithDeviceID(deviceID string) *Logger {
	return l.WithField(l.config.DeviceIDField, deviceID)
}

// WithTransactionID adds a transaction ID field to the logger
func (l *Logger) WithTransactionID(txID string) *Logger {
	return l.WithField(l.config.TransactionField, txID)
}

// Debug logs at debug level
func (l *Logger) Debug(msg string, fields ...zap.Field) {
	allFields := append(l.defaultFields, fields...)
	l.zap.Debug(msg, allFields...)
}

// Debugf logs at debug level with formatting
func (l *Logger) Debugf(template string, args ...interface{}) {
	l.sugar.With(l.fieldsToSugarArgs()...).Debugf(template, args...)
}

// Info logs at info level
func (l *Logger) Info(msg string, fields ...zap.Field) {
	allFields := append(l.defaultFields, fields...)
	l.zap.Info(msg, allFields...)
}

// Infof logs at info level with formatting
func (l *Logger) Infof(template string, args ...interface{}) {
	l.sugar.With(l.fieldsToSugarArgs()...).Infof(template, args...)
}

// Warn logs at warn level
func (l *Logger) Warn(msg string, fields ...zap.Field) {
	allFields := append(l.defaultFields, fields...)
	l.zap.Warn(msg, allFields...)
}

// Warnf logs at warn level with formatting
func (l *Logger) Warnf(template string, args ...interface{}) {
	l.sugar.With(l.fieldsToSugarArgs()...).Warnf(template, args...)
}

// Error logs at error level
func (l *Logger) Error(msg string, fields ...zap.Field) {
	allFields := append(l.defaultFields, fields...)
	l.zap.Error(msg, allFields...)
}

// Errorf logs at error level with formatting
func (l *Logger) Errorf(template string, args ...interface{}) {
	l.sugar.With(l.fieldsToSugarArgs()...).Errorf(template, args...)
}

// Fatal logs at fatal level and then calls os.Exit(1)
func (l *Logger) Fatal(msg string, fields ...zap.Field) {
	allFields := append(l.defaultFields, fields...)
	l.zap.Fatal(msg, allFields...)
}

// Fatalf logs at fatal level with formatting and then calls os.Exit(1)
func (l *Logger) Fatalf(template string, args ...interface{}) {
	l.sugar.With(l.fieldsToSugarArgs()...).Fatalf(template, args...)
}

// SetLevel changes the logging level
func (l *Logger) SetLevel(level LogLevel) {
	l.level.SetLevel(getZapLevel(level))
}

// Sync flushes any buffered log entries
func (l *Logger) Sync() error {
	return l.zap.Sync()
}

// Close syncs and closes the logger
func (l *Logger) Close() error {
	return l.Sync()
}

// GetZapLogger returns the underlying zap logger
func (l *Logger) GetZapLogger() *zap.Logger {
	return l.zap
}

// Global logger functions for convenience

// Debug logs at debug level using the default logger
func Debug(msg string, fields ...zap.Field) {
	GetDefaultLogger().Debug(msg, fields...)
}

// Debugf logs at debug level with formatting using the default logger
func Debugf(template string, args ...interface{}) {
	GetDefaultLogger().Debugf(template, args...)
}

// Info logs at info level using the default logger
func Info(msg string, fields ...zap.Field) {
	GetDefaultLogger().Info(msg, fields...)
}

// Infof logs at info level with formatting using the default logger
func Infof(template string, args ...interface{}) {
	GetDefaultLogger().Infof(template, args...)
}

// Warn logs at warn level using the default logger
func Warn(msg string, fields ...zap.Field) {
	GetDefaultLogger().Warn(msg, fields...)
}

// Warnf logs at warn level with formatting using the default logger
func Warnf(template string, args ...interface{}) {
	GetDefaultLogger().Warnf(template, args...)
}

// Error logs at error level using the default logger
func Error(msg string, fields ...zap.Field) {
	GetDefaultLogger().Error(msg, fields...)
}

// Errorf logs at error level with formatting using the default logger
func Errorf(template string, args ...interface{}) {
	GetDefaultLogger().Errorf(template, args...)
}

// Fatal logs at fatal level and then calls os.Exit(1) using the default logger
func Fatal(msg string, fields ...zap.Field) {
	GetDefaultLogger().Fatal(msg, fields...)
}

// Fatalf logs at fatal level with formatting and then calls os.Exit(1) using the default logger
func Fatalf(template string, args ...interface{}) {
	GetDefaultLogger().Fatalf(template, args...)
}

// WithField adds a field to the default logger
func WithField(key string, value interface{}) *Logger {
	return GetDefaultLogger().WithField(key, value)
}

// WithFields adds multiple fields to the default logger
func WithFields(fields map[string]interface{}) *Logger {
	return GetDefaultLogger().WithFields(fields)
}

// WithDeviceID adds a device ID field to the default logger
func WithDeviceID(deviceID string) *Logger {
	return GetDefaultLogger().WithDeviceID(deviceID)
}

// WithTransactionID adds a transaction ID field to the default logger
func WithTransactionID(txID string) *Logger {
	return GetDefaultLogger().WithTransactionID(txID)
}

// Helper functions

// Convert LogLevel to zapcore.Level
func getZapLevel(level LogLevel) zapcore.Level {
	switch level {
	case DebugLevel:
		return zapcore.DebugLevel
	case InfoLevel:
		return zapcore.InfoLevel
	case WarnLevel:
		return zapcore.WarnLevel
	case ErrorLevel:
		return zapcore.ErrorLevel
	case FatalLevel:
		return zapcore.FatalLevel
	default:
		return zapcore.InfoLevel
	}
}

// Convert fields map to sugar args
func (l *Logger) fieldsToSugarArgs() []interface{} {
	l.fieldsMutex.RLock()
	defer l.fieldsMutex.RUnlock()

	args := make([]interface{}, 0, len(l.fields)*2)
	for k, v := range l.fields {
		args = append(args, k, v)
	}
	return args
}

// Initialize logs with timestamp and version
func init() {
	// Record start time
	startTime := time.Now()

	// Get logger
	logger := GetDefaultLogger()

	// Log startup
	logger.Info("Logger initialized",
		zap.String("version", "1.0.0"),
		zap.Time("startup_time", startTime),
	)
}
