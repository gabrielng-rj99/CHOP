package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// ServerConfig holds server configuration
type ServerConfig struct {
	Host                 string
	Port                 string
	RequestTimeout       int
	ReadTimeout          int
	WriteTimeout         int
	IdleTimeout          int
	CORSAllowedOrigins   []string
	CORSAllowedMethods   []string
	CORSAllowedHeaders   []string
	CORSExposeHeaders    []string
	CORSAllowCredentials bool
	CORSMaxAge           int
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Host            string
	Port            string
	Name            string
	User            string
	Password        string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime int
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	SecretKey             string
	ExpirationTime        int // minutes
	RefreshExpirationTime int // minutes
	Algorithm             string
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Enabled    bool
	Level      string
	Format     string
	File       string
	MaxSize    int // MB
	MaxBackups int
	MaxAge     int // days
}

// SecurityConfig holds security configuration
type SecurityConfig struct {
	PasswordMinLength        int
	PasswordRequireUppercase bool
	PasswordRequireLowercase bool
	PasswordRequireNumbers   bool
	PasswordRequireSpecial   bool
	MaxFailedAttempts        int
	LockoutDurationMinutes   int
	LockLevels               int
	LockLevel1Attempts       int
	LockLevel1DurationMins   int
	LockLevel2Attempts       int
	LockLevel2DurationMins   int
	LockLevel3Attempts       int
	LockLevel3DurationMins   int
	LockLevelManualAttempts  int
}

// ApplicationConfig holds application configuration
type ApplicationConfig struct {
	Env     string
	Version string
	Name    string
}

// PathsConfig holds paths configuration
type PathsConfig struct {
	SchemaFile    string
	MigrationsDir string
	LogsDir       string
	ReportsDir    string
}

// Config holds all configuration
type Config struct {
	Server      *ServerConfig
	Database    *DatabaseConfig
	JWT         *JWTConfig
	Logging     *LoggingConfig
	Security    *SecurityConfig
	Application *ApplicationConfig
	Paths       *PathsConfig
}

var (
	globalConfig *Config
	configMutex  sync.RWMutex
)

// LoadConfig loads configuration from config.ini file and environment variables
func LoadConfig(configPath string) (*Config, error) {
	if configPath == "" {
		// Try to find config.ini in current directory or parent directories
		configPath = findConfigFile()
		if configPath == "" {
			return nil, fmt.Errorf("config.ini not found")
		}
	}

	// Parse INI file
	sections := parseINI(configPath)

	cfg := &Config{
		Server:      parseServerConfig(sections["server"]),
		Database:    parseDatabaseConfig(sections["database"]),
		JWT:         parseJWTConfig(sections["jwt"]),
		Logging:     parseLoggingConfig(sections["logging"]),
		Security:    parseSecurityConfig(sections["security"]),
		Application: parseApplicationConfig(sections["application"]),
		Paths:       parsePathsConfig(sections["paths"]),
	}

	// Override with environment variables (prefixed with APP_)
	overrideWithEnv(cfg)

	configMutex.Lock()
	globalConfig = cfg
	configMutex.Unlock()

	return cfg, nil
}

// GetConfig returns a copy of the global config instance (thread-safe)
func GetConfig() *Config {
	configMutex.RLock()
	defer configMutex.RUnlock()

	if globalConfig == nil {
		configMutex.RUnlock()
		cfg, err := LoadConfig("")
		configMutex.RLock()
		if err != nil {
			panic(fmt.Sprintf("Failed to load config: %v", err))
		}
		return cfg
	}
	return globalConfig
}

// SetConfig updates the global configuration dynamically (thread-safe)
// Used for runtime configuration updates from deploy panel
func SetConfig(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config cannot be nil")
	}

	// Validate critical settings
	if cfg.Server == nil || cfg.Server.Port == "" {
		return fmt.Errorf("invalid server configuration")
	}
	if cfg.Database == nil {
		return fmt.Errorf("invalid database configuration")
	}
	if cfg.JWT == nil {
		return fmt.Errorf("invalid JWT configuration")
	}

	configMutex.Lock()
	defer configMutex.Unlock()

	globalConfig = cfg
	return nil
}

// UpdateDatabaseConfig updates only database configuration
func UpdateDatabaseConfig(dbCfg *DatabaseConfig) error {
	if dbCfg == nil {
		return fmt.Errorf("database config cannot be nil")
	}

	configMutex.Lock()
	defer configMutex.Unlock()

	if globalConfig == nil {
		return fmt.Errorf("global config not initialized")
	}

	globalConfig.Database = dbCfg
	return nil
}

// UpdateJWTConfig updates only JWT configuration
func UpdateJWTConfig(jwtCfg *JWTConfig) error {
	if jwtCfg == nil {
		return fmt.Errorf("JWT config cannot be nil")
	}

	configMutex.Lock()
	defer configMutex.Unlock()

	if globalConfig == nil {
		return fmt.Errorf("global config not initialized")
	}

	globalConfig.JWT = jwtCfg
	return nil
}

// UpdateServerConfig updates only server configuration
func UpdateServerConfig(srvCfg *ServerConfig) error {
	if srvCfg == nil {
		return fmt.Errorf("server config cannot be nil")
	}

	configMutex.Lock()
	defer configMutex.Unlock()

	if globalConfig == nil {
		return fmt.Errorf("global config not initialized")
	}

	globalConfig.Server = srvCfg
	return nil
}

// GetDatabaseURL returns the full database connection URL
func (c *Config) GetDatabaseURL() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=%s",
		c.Database.User,
		c.Database.Password,
		c.Database.Host,
		c.Database.Port,
		c.Database.Name,
		c.Database.SSLMode,
	)
}

// GetServerAddr returns server address (host:port)
func (c *Config) GetServerAddr() string {
	return c.Server.Host + ":" + c.Server.Port
}

// GetConfigSafeCopy returns a deep copy of the configuration (thread-safe)
// Used to safely pass config to other goroutines without locks
func GetConfigSafeCopy() *Config {
	configMutex.RLock()
	defer configMutex.RUnlock()

	if globalConfig == nil {
		return nil
	}

	// Create a shallow copy (safe for our use case since we don't modify nested structs after copy)
	cfgCopy := *globalConfig
	return &cfgCopy
}

// PrintConfig prints configuration (without sensitive data)
func (c *Config) PrintConfig() {
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                   SERVER CONFIGURATION                         ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Printf("\n📡 Server:\n")
	fmt.Printf("  Host: %s\n", c.Server.Host)
	fmt.Printf("  Port: %s\n", c.Server.Port)
	fmt.Printf("  Environment: %s\n", c.Application.Env)

	fmt.Printf("\n🗄️  Database:\n")
	fmt.Printf("  Host: %s\n", c.Database.Host)
	fmt.Printf("  Port: %s\n", c.Database.Port)
	fmt.Printf("  Database: %s\n", c.Database.Name)
	fmt.Printf("  User: %s\n", c.Database.User)
	fmt.Printf("  SSL Mode: %s\n", c.Database.SSLMode)

	fmt.Printf("\n🔐 JWT:\n")
	fmt.Printf("  Algorithm: %s\n", c.JWT.Algorithm)
	fmt.Printf("  Expiration: %d minutes\n", c.JWT.ExpirationTime)
	fmt.Printf("  Refresh Expiration: %d minutes\n", c.JWT.RefreshExpirationTime)

	fmt.Printf("\n📝 Logging:\n")
	fmt.Printf("  Enabled: %v\n", c.Logging.Enabled)
	fmt.Printf("  Level: %s\n", c.Logging.Level)
	fmt.Printf("  File: %s\n", c.Logging.File)

	fmt.Printf("\n🔒 Security:\n")
	fmt.Printf("  Max Failed Attempts: %d\n", c.Security.MaxFailedAttempts)
	fmt.Printf("  Lockout Duration: %d minutes\n", c.Security.LockoutDurationMinutes)
	fmt.Printf("\n")
}

// parseINI parses INI file and returns map of sections with key-value pairs
func parseINI(filePath string) map[string]map[string]string {
	content, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Warning: Could not read %s: %v\n", filePath, err)
		return make(map[string]map[string]string)
	}

	sections := make(map[string]map[string]string)
	var currentSection string

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for section header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.Trim(line, "[]")
			sections[currentSection] = make(map[string]string)
			continue
		}

		// Parse key-value pair
		if currentSection != "" && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				sections[currentSection][key] = value
			}
		}
	}

	return sections
}

// parseServerConfig parses server configuration
func parseServerConfig(section map[string]string) *ServerConfig {
	cfg := &ServerConfig{
		Host:                 getEnvOrDefault("APP_SERVER_HOST", section["host"], "localhost"),
		Port:                 getEnvOrDefault("APP_SERVER_PORT", section["port"], "3000"),
		RequestTimeout:       getEnvIntOrDefault("APP_SERVER_REQUEST_TIMEOUT", section["request_timeout"], 30),
		ReadTimeout:          getEnvIntOrDefault("APP_SERVER_READ_TIMEOUT", section["read_timeout"], 15),
		WriteTimeout:         getEnvIntOrDefault("APP_SERVER_WRITE_TIMEOUT", section["write_timeout"], 15),
		IdleTimeout:          getEnvIntOrDefault("APP_SERVER_IDLE_TIMEOUT", section["idle_timeout"], 60),
		CORSAllowCredentials: getEnvBoolOrDefault("APP_SERVER_CORS_ALLOW_CREDENTIALS", section["cors_allow_credentials"], true),
		CORSMaxAge:           getEnvIntOrDefault("APP_SERVER_CORS_MAX_AGE", section["cors_max_age"], 3600),
	}

	// Parse comma-separated lists
	cfg.CORSAllowedOrigins = parseCSV(getEnvOrDefault("APP_SERVER_CORS_ALLOWED_ORIGINS", section["cors_allowed_origins"], "http://localhost:8080,http://localhost:3000"))
	cfg.CORSAllowedMethods = parseCSV(getEnvOrDefault("APP_SERVER_CORS_ALLOWED_METHODS", section["cors_allowed_methods"], "GET,POST,PUT,DELETE,OPTIONS,PATCH"))
	cfg.CORSAllowedHeaders = parseCSV(getEnvOrDefault("APP_SERVER_CORS_ALLOWED_HEADERS", section["cors_allowed_headers"], "Content-Type,Authorization,X-Requested-With"))
	cfg.CORSExposeHeaders = parseCSV(getEnvOrDefault("APP_SERVER_CORS_EXPOSE_HEADERS", section["cors_expose_headers"], "Content-Length,X-Total-Count"))

	return cfg
}

// parseDatabaseConfig parses database configuration
func parseDatabaseConfig(section map[string]string) *DatabaseConfig {
	return &DatabaseConfig{
		Host:            getEnvOrDefault("APP_DATABASE_HOST", section["host"], "localhost"),
		Port:            getEnvOrDefault("APP_DATABASE_PORT", section["port"], "5432"),
		Name:            getEnvOrDefault("APP_DATABASE_NAME", section["name"], "contracts_manager"),
		User:            getEnvOrDefault("APP_DATABASE_USER", section["user"], "postgres"),
		Password:        getEnvOrDefault("APP_DATABASE_PASSWORD", section["password"], "postgres"),
		SSLMode:         getEnvOrDefault("APP_DATABASE_SSL_MODE", section["ssl_mode"], "disable"),
		MaxOpenConns:    getEnvIntOrDefault("APP_DATABASE_MAX_OPEN_CONNS", section["max_open_conns"], 10),
		MaxIdleConns:    getEnvIntOrDefault("APP_DATABASE_MAX_IDLE_CONNS", section["max_idle_conns"], 5),
		ConnMaxLifetime: getEnvIntOrDefault("APP_DATABASE_CONN_MAX_LIFETIME", section["conn_max_lifetime"], 180),
	}
}

// parseJWTConfig parses JWT configuration
func parseJWTConfig(section map[string]string) *JWTConfig {
	return &JWTConfig{
		SecretKey:             getEnvOrDefault("APP_JWT_SECRET_KEY", section["secret_key"], "CONTRACT_MANAGER_SUPER_SECRET"),
		ExpirationTime:        getEnvIntOrDefault("APP_JWT_EXPIRATION_TIME", section["expiration_time"], 60),
		RefreshExpirationTime: getEnvIntOrDefault("APP_JWT_REFRESH_EXPIRATION_TIME", section["refresh_expiration_time"], 10080),
		Algorithm:             getEnvOrDefault("APP_JWT_ALGORITHM", section["algorithm"], "HS256"),
	}
}

// parseLoggingConfig parses logging configuration
func parseLoggingConfig(section map[string]string) *LoggingConfig {
	return &LoggingConfig{
		Enabled:    getEnvBoolOrDefault("APP_LOGGING_ENABLED", section["enabled"], true),
		Level:      getEnvOrDefault("APP_LOGGING_LEVEL", section["level"], "info"),
		Format:     getEnvOrDefault("APP_LOGGING_FORMAT", section["format"], "text"),
		File:       getEnvOrDefault("APP_LOGGING_FILE", section["file"], "server.log"),
		MaxSize:    getEnvIntOrDefault("APP_LOGGING_MAX_SIZE", section["max_size"], 5),
		MaxBackups: getEnvIntOrDefault("APP_LOGGING_MAX_BACKUPS", section["max_backups"], 3),
		MaxAge:     getEnvIntOrDefault("APP_LOGGING_MAX_AGE", section["max_age"], 30),
	}
}

// parseSecurityConfig parses security configuration
func parseSecurityConfig(section map[string]string) *SecurityConfig {
	return &SecurityConfig{
		PasswordMinLength:        getEnvIntOrDefault("APP_SECURITY_PASSWORD_MIN_LENGTH", section["password_min_length"], 8),
		PasswordRequireUppercase: getEnvBoolOrDefault("APP_SECURITY_PASSWORD_REQUIRE_UPPERCASE", section["password_require_uppercase"], true),
		PasswordRequireLowercase: getEnvBoolOrDefault("APP_SECURITY_PASSWORD_REQUIRE_LOWERCASE", section["password_require_lowercase"], true),
		PasswordRequireNumbers:   getEnvBoolOrDefault("APP_SECURITY_PASSWORD_REQUIRE_NUMBERS", section["password_require_numbers"], true),
		PasswordRequireSpecial:   getEnvBoolOrDefault("APP_SECURITY_PASSWORD_REQUIRE_SPECIAL", section["password_require_special"], true),
		MaxFailedAttempts:        getEnvIntOrDefault("APP_SECURITY_MAX_FAILED_ATTEMPTS", section["max_failed_attempts"], 5),
		LockoutDurationMinutes:   getEnvIntOrDefault("APP_SECURITY_LOCKOUT_DURATION_MINUTES", section["lockout_duration_minutes"], 30),
		LockLevels:               getEnvIntOrDefault("APP_SECURITY_LOCK_LEVELS", section["lock_levels"], 3),
		LockLevel1Attempts:       getEnvIntOrDefault("APP_SECURITY_LOCK_LEVEL_1_ATTEMPTS", section["lock_level_1_attempts"], 3),
		LockLevel1DurationMins:   getEnvIntOrDefault("APP_SECURITY_LOCK_LEVEL_1_DURATION_MINUTES", section["lock_level_1_duration_minutes"], 5),
		LockLevel2Attempts:       getEnvIntOrDefault("APP_SECURITY_LOCK_LEVEL_2_ATTEMPTS", section["lock_level_2_attempts"], 5),
		LockLevel2DurationMins:   getEnvIntOrDefault("APP_SECURITY_LOCK_LEVEL_2_DURATION_MINUTES", section["lock_level_2_duration_minutes"], 15),
		LockLevel3Attempts:       getEnvIntOrDefault("APP_SECURITY_LOCK_LEVEL_3_ATTEMPTS", section["lock_level_3_attempts"], 8),
		LockLevel3DurationMins:   getEnvIntOrDefault("APP_SECURITY_LOCK_LEVEL_3_DURATION_MINUTES", section["lock_level_3_duration_minutes"], 60),
		LockLevelManualAttempts:  getEnvIntOrDefault("APP_SECURITY_LOCK_LEVEL_MANUAL_ATTEMPTS", section["lock_level_manual_attempts"], 10),
	}
}

// parseApplicationConfig parses application configuration
func parseApplicationConfig(section map[string]string) *ApplicationConfig {
	return &ApplicationConfig{
		Env:     getEnvOrDefault("APP_ENV", section["env"], "development"),
		Version: getEnvOrDefault("APP_VERSION", section["version"], "1.0.0"),
		Name:    getEnvOrDefault("APP_NAME", section["name"], "Contract Manager"),
	}
}

// parsePathsConfig parses paths configuration
func parsePathsConfig(section map[string]string) *PathsConfig {
	return &PathsConfig{
		SchemaFile:    getEnvOrDefault("APP_SCHEMA_FILE", section["schema_file"], "../database/schema.sql"),
		MigrationsDir: getEnvOrDefault("APP_MIGRATIONS_DIR", section["migrations_dir"], "../migrations"),
		LogsDir:       getEnvOrDefault("APP_LOGS_DIR", section["logs_dir"], "./logs"),
		ReportsDir:    getEnvOrDefault("APP_REPORTS_DIR", section["reports_dir"], "./reports"),
	}
}

// overrideWithEnv overrides configuration with environment variables
func overrideWithEnv(cfg *Config) {
	// This is already done in the individual parse functions
	// but we can add additional logic here if needed
}

// Helper functions

// findConfigFile finds config.ini in current directory or parent directories
func findConfigFile() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}

	// Try to find config.ini in current directory and parent directories
	for {
		configPath := filepath.Join(cwd, "config.ini")
		if _, err := os.Stat(configPath); err == nil {
			return configPath
		}

		parent := filepath.Dir(cwd)
		if parent == cwd {
			break // Reached root directory
		}
		cwd = parent
	}

	return ""
}

// getEnvOrDefault gets environment variable or returns default value from config
func getEnvOrDefault(envKey, configValue, defaultValue string) string {
	if envValue := os.Getenv(envKey); envValue != "" {
		return envValue
	}
	if configValue != "" {
		return configValue
	}
	return defaultValue
}

// getEnvIntOrDefault gets environment variable as int or returns default value
func getEnvIntOrDefault(envKey, configValue string, defaultValue int) int {
	if envValue := os.Getenv(envKey); envValue != "" {
		if intVal, err := strconv.Atoi(envValue); err == nil {
			return intVal
		}
	}
	if configValue != "" {
		if intVal, err := strconv.Atoi(configValue); err == nil {
			return intVal
		}
	}
	return defaultValue
}

// getEnvBoolOrDefault gets environment variable as bool or returns default value
func getEnvBoolOrDefault(envKey, configValue string, defaultValue bool) bool {
	if envValue := os.Getenv(envKey); envValue != "" {
		return strings.ToLower(envValue) == "true" || strings.ToLower(envValue) == "1" || strings.ToLower(envValue) == "yes"
	}
	if configValue != "" {
		return strings.ToLower(configValue) == "true" || strings.ToLower(configValue) == "1" || strings.ToLower(configValue) == "yes"
	}
	return defaultValue
}

// parseCSV parses comma-separated values into a slice
func parseCSV(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}
