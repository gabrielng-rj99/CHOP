package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Config holds all parsed configuration from INI files
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Docker   DockerConfig
	Services ServicesConfig
	JWT      JWTConfig
	Logging  LoggingConfig
	Security SecurityConfig
	App      AppConfig
	Paths    PathsConfig
}

type ServerConfig struct {
	Host              string
	Port              string
	RequestTimeout    int
	ReadTimeout       int
	WriteTimeout      int
	IdleTimeout       int
	CORSOrigins       []string
	CORSMethods       []string
	CORSHeaders       []string
	CORSExposeHeaders []string
	CORSAllowCreds    bool
	CORSMaxAge        int
}

type DatabaseConfig struct {
	ContainerName string
	Host          string
	Port          string
	Name          string
	User          string
	SSLMode       string
	MaxOpenConns  int
	MaxIdleConns  int
	ConnMaxLife   int
}

type DockerConfig struct {
	ComposeFile       string
	NetworkName       string
	PostgresContainer string
	PostgresPort      string
	PostgresVolume    string
	BackendContainer  string
	BackendPort       string
	FrontendContainer string
	FrontendPort      string
	FrontendNginxPort string
}

type ServicesConfig struct {
	PostgresContainer string
	BackendContainer  string
	FrontendContainer string
	FrontendHostPort  string
	FrontendContPort  string
	BackendHostPort   string
	BackendContPort   string
	DatabaseHostPort  string
	DatabaseContPort  string
	BackendHealth     string
	BackendTimeout    int
	DBHealthUser      string
}

type JWTConfig struct {
	ExpirationTime        int
	RefreshExpirationTime int
	Algorithm             string
}

type LoggingConfig struct {
	Enabled    bool
	Level      string
	Format     string
	File       string
	MaxSize    int
	MaxBackups int
	MaxAge     int
}

type SecurityConfig struct {
	PasswordMinLength     int
	PasswordUppercase     bool
	PasswordLowercase     bool
	PasswordNumbers       bool
	PasswordSpecial       bool
	MaxFailedAttempts     int
	LockoutDuration       int
	LockLevels            int
	LockLevel1Attempts    int
	LockLevel1Duration    int
	LockLevel2Attempts    int
	LockLevel2Duration    int
	LockLevel3Attempts    int
	LockLevel3Duration    int
	LockLevelManualAtmpts int
}

type AppConfig struct {
	Env     string
	Version string
	Name    string
}

type PathsConfig struct {
	SchemaFile    string
	MigrationsDir string
	LogsDir       string
	ReportsDir    string
}

// LoadConfig loads and parses the configuration file
func LoadConfig(configFile string) (*Config, error) {
	// Ensure config file path is absolute
	if !filepath.IsAbs(configFile) {
		rootDir, err := getProjectRoot()
		if err != nil {
			return nil, fmt.Errorf("failed to get project root: %v", err)
		}
		configFile = filepath.Join(rootDir, configFile)
	}

	file, err := os.Open(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file %s: %v", configFile, err)
	}
	defer file.Close()

	config := &Config{}
	scanner := bufio.NewScanner(file)
	currentSection := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for section headers
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.TrimPrefix(strings.TrimSuffix(line, "]"), "[")
			continue
		}

		// Parse key=value pairs
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}

			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			parseConfigValue(config, currentSection, key, value)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading config file: %v", err)
	}

	// Interpolate variables in all sections
	interpolateAllVars(config)

	return config, nil
}

// interpolateAllVars performs variable interpolation for all sections
func interpolateAllVars(config *Config) {
	// Collect all raw values first
	allValues := make(map[string]map[string]string)

	// Store server section
	allValues["server"] = map[string]string{
		"backend_port":  config.Server.Port,
		"frontend_port": "",
	}

	// Store docker section
	allValues["docker"] = map[string]string{
		"backend_port":       config.Docker.BackendPort,
		"frontend_port":      config.Docker.FrontendPort,
		"postgres_port":      config.Docker.PostgresPort,
		"postgres_container": config.Docker.PostgresContainer,
		"backend_container":  config.Docker.BackendContainer,
		"frontend_container": config.Docker.FrontendContainer,
	}

	// Interpolate server CORS origins
	config.Server.CORSOrigins = interpolateStringSlice(config.Server.CORSOrigins, allValues)

	// Interpolate database port
	config.Database.Port = interpolateString(config.Database.Port, allValues)
	config.Database.ContainerName = interpolateString(config.Database.ContainerName, allValues)

	// Interpolate docker config
	config.Docker.BackendPort = interpolateString(config.Docker.BackendPort, allValues)
	config.Docker.FrontendPort = interpolateString(config.Docker.FrontendPort, allValues)
	config.Docker.PostgresPort = interpolateString(config.Docker.PostgresPort, allValues)
}

// interpolateString replaces ${key} references with values from allValues map
func interpolateString(value string, allValues map[string]map[string]string) string {
	varRegex := regexp.MustCompile(`\$\{([^}]+)\}`)

	return varRegex.ReplaceAllStringFunc(value, func(match string) string {
		matches := varRegex.FindStringSubmatch(match)
		if len(matches) < 2 {
			return match
		}

		varName := matches[1]

		// First try to find in docker section (most common)
		if dockerVals, ok := allValues["docker"]; ok {
			if val, ok := dockerVals[varName]; ok && val != "" {
				return val
			}
		}

		// Then try server section
		if serverVals, ok := allValues["server"]; ok {
			if val, ok := serverVals[varName]; ok && val != "" {
				return val
			}
		}

		// Return original if not found
		return match
	})
}

// interpolateStringSlice interpolates all strings in a slice
func interpolateStringSlice(values []string, allValues map[string]map[string]string) []string {
	result := make([]string, len(values))
	for i, v := range values {
		result[i] = interpolateString(v, allValues)
	}
	return result
}

// parseConfigValue parses a configuration key-value pair and assigns it to the appropriate struct
func parseConfigValue(config *Config, section, key, value string) {
	switch section {
	case "server":
		parseServerConfig(&config.Server, key, value)
	case "database":
		parseDatabaseConfig(&config.Database, key, value)
	case "docker":
		parseDockerConfig(&config.Docker, key, value)
	case "services":
		parseServicesConfig(&config.Services, key, value)
	case "jwt":
		parseJWTConfig(&config.JWT, key, value)
	case "logging":
		parseLoggingConfig(&config.Logging, key, value)
	case "security":
		parseSecurityConfig(&config.Security, key, value)
	case "application":
		parseAppConfig(&config.App, key, value)
	case "paths":
		parsePathsConfig(&config.Paths, key, value)
	}
}

func parseServerConfig(s *ServerConfig, key, value string) {
	switch key {
	case "host":
		s.Host = value
	case "port":
		s.Port = value
	case "request_timeout":
		s.RequestTimeout = toInt(value)
	case "read_timeout":
		s.ReadTimeout = toInt(value)
	case "write_timeout":
		s.WriteTimeout = toInt(value)
	case "idle_timeout":
		s.IdleTimeout = toInt(value)
	case "cors_allowed_origins":
		s.CORSOrigins = parseCSV(value)
	case "cors_allowed_methods":
		s.CORSMethods = parseCSV(value)
	case "cors_allowed_headers":
		s.CORSHeaders = parseCSV(value)
	case "cors_expose_headers":
		s.CORSExposeHeaders = parseCSV(value)
	case "cors_allow_credentials":
		s.CORSAllowCreds = toBool(value)
	case "cors_max_age":
		s.CORSMaxAge = toInt(value)
	}
}

func parseDatabaseConfig(d *DatabaseConfig, key, value string) {
	switch key {
	case "container_name":
		d.ContainerName = value
	case "host":
		d.Host = value
	case "port":
		d.Port = value
	case "name":
		d.Name = value
	case "user":
		d.User = value
	case "ssl_mode":
		d.SSLMode = value
	case "max_open_conns":
		d.MaxOpenConns = toInt(value)
	case "max_idle_conns":
		d.MaxIdleConns = toInt(value)
	case "conn_max_lifetime":
		d.ConnMaxLife = toInt(value)
	}
}

func parseDockerConfig(d *DockerConfig, key, value string) {
	switch key {
	case "compose_file":
		d.ComposeFile = value
	case "network_name":
		d.NetworkName = value
	case "postgres_container":
		d.PostgresContainer = value
	case "postgres_port":
		d.PostgresPort = value
	case "postgres_volume":
		d.PostgresVolume = value
	case "backend_container":
		d.BackendContainer = value
	case "backend_port":
		d.BackendPort = value
	case "frontend_container":
		d.FrontendContainer = value
	case "frontend_port":
		d.FrontendPort = value
	case "frontend_nginx_port":
		d.FrontendNginxPort = value
	}
}

func parseServicesConfig(s *ServicesConfig, key, value string) {
	switch key {
	case "postgres_container":
		s.PostgresContainer = value
	case "backend_container":
		s.BackendContainer = value
	case "frontend_container":
		s.FrontendContainer = value
	case "frontend_host_port":
		s.FrontendHostPort = value
	case "frontend_container_port":
		s.FrontendContPort = value
	case "backend_host_port":
		s.BackendHostPort = value
	case "backend_container_port":
		s.BackendContPort = value
	case "database_host_port":
		s.DatabaseHostPort = value
	case "database_container_port":
		s.DatabaseContPort = value
	case "backend_health_endpoint":
		s.BackendHealth = value
	case "backend_health_timeout":
		s.BackendTimeout = toInt(value)
	case "database_healthcheck_user":
		s.DBHealthUser = value
	}
}

func parseJWTConfig(j *JWTConfig, key, value string) {
	switch key {
	case "expiration_time":
		j.ExpirationTime = toInt(value)
	case "refresh_expiration_time":
		j.RefreshExpirationTime = toInt(value)
	case "algorithm":
		j.Algorithm = value
	}
}

func parseLoggingConfig(l *LoggingConfig, key, value string) {
	switch key {
	case "enabled":
		l.Enabled = toBool(value)
	case "level":
		l.Level = value
	case "format":
		l.Format = value
	case "file":
		l.File = value
	case "max_size":
		l.MaxSize = toInt(value)
	case "max_backups":
		l.MaxBackups = toInt(value)
	case "max_age":
		l.MaxAge = toInt(value)
	}
}

func parseSecurityConfig(s *SecurityConfig, key, value string) {
	switch key {
	case "password_min_length":
		s.PasswordMinLength = toInt(value)
	case "password_require_uppercase":
		s.PasswordUppercase = toBool(value)
	case "password_require_lowercase":
		s.PasswordLowercase = toBool(value)
	case "password_require_numbers":
		s.PasswordNumbers = toBool(value)
	case "password_require_special":
		s.PasswordSpecial = toBool(value)
	case "max_failed_attempts":
		s.MaxFailedAttempts = toInt(value)
	case "lockout_duration_minutes":
		s.LockoutDuration = toInt(value)
	case "lock_levels":
		s.LockLevels = toInt(value)
	case "lock_level_1_attempts":
		s.LockLevel1Attempts = toInt(value)
	case "lock_level_1_duration_minutes":
		s.LockLevel1Duration = toInt(value)
	case "lock_level_2_attempts":
		s.LockLevel2Attempts = toInt(value)
	case "lock_level_2_duration_minutes":
		s.LockLevel2Duration = toInt(value)
	case "lock_level_3_attempts":
		s.LockLevel3Attempts = toInt(value)
	case "lock_level_3_duration_minutes":
		s.LockLevel3Duration = toInt(value)
	case "lock_level_manual_attempts":
		s.LockLevelManualAtmpts = toInt(value)
	}
}

func parseAppConfig(a *AppConfig, key, value string) {
	switch key {
	case "env":
		a.Env = value
	case "version":
		a.Version = value
	case "name":
		a.Name = value
	}
}

func parsePathsConfig(p *PathsConfig, key, value string) {
	switch key {
	case "schema_file":
		p.SchemaFile = value
	case "migrations_dir":
		p.MigrationsDir = value
	case "logs_dir":
		p.LogsDir = value
	case "reports_dir":
		p.ReportsDir = value
	}
}

// Helper functions for type conversion
func toInt(s string) int {
	val, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return val
}

func toBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "true" || s == "yes" || s == "1" || s == "on"
}

func parseCSV(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if len(trimmed) > 0 {
			result = append(result, trimmed)
		}
	}
	return result
}

// GetServiceURL returns the formatted URL for a service
func (c *Config) GetServiceURL(service string) string {
	switch service {
	case "backend":
		return fmt.Sprintf("http://localhost:%s", c.Docker.BackendPort)
	case "frontend":
		return fmt.Sprintf("http://localhost:%s", c.Docker.FrontendNginxPort)
	case "database":
		return fmt.Sprintf("localhost:%s", c.Docker.PostgresPort)
	default:
		return ""
	}
}

// GetDatabaseConnString returns the database connection string
func (c *Config) GetDatabaseConnString() string {
	return fmt.Sprintf("postgres://%s@%s:%s/%s?sslmode=%s",
		c.Database.User,
		c.Database.Host,
		c.Database.Port,
		c.Database.Name,
		c.Database.SSLMode,
	)
}
