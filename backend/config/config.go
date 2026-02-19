/*
 * Client Hub Open Project
 * Copyright (C) 2025 Client Hub Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	globalConfig *Config
	configOnce   sync.Once
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	Logging  LoggingConfig
	Security SecurityConfig
	App      AppConfig
	Paths    PathsConfig
}

type ServerConfig struct {
	Host              string
	Port              string
	RequestTimeout    time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	CORSOrigins       []string
	CORSMethods       []string
	CORSHeaders       []string
	CORSExposeHeaders []string
	CORSAllowCreds    bool
	CORSMaxAge        int
}

type DatabaseConfig struct {
	Host         string
	Port         string
	Name         string
	User         string
	Password     string
	SSLMode      string
	MaxOpenConns int
	MaxIdleConns int
	ConnMaxLife  time.Duration
}

type JWTConfig struct {
	SecretKey             string
	ExpirationTime        time.Duration
	RefreshExpirationTime time.Duration
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
	LockoutDuration       time.Duration
	LockLevels            int
	LockLevel1Attempts    int
	LockLevel1Duration    time.Duration
	LockLevel2Attempts    int
	LockLevel2Duration    time.Duration
	LockLevel3Attempts    int
	LockLevel3Duration    time.Duration
	LockLevelManualAtmpts int
	RateLimit             int
	RateBurst             int
}

type AppConfig struct {
	Env     string
	Version string
	Name    string
}

type PathsConfig struct {
	SchemaDir     string
	MigrationsDir string
	LogsDir       string
	ReportsDir    string
}

// LoadConfig loads configuration from environment variables with fallback defaults
func LoadConfig() (*Config, error) {
	config := &Config{
		Server: ServerConfig{
			Host:              getEnv("SERVER_HOST", "0.0.0.0"),
			Port:              getEnv("API_PORT", "3000"),
			RequestTimeout:    getEnvDuration("REQUEST_TIMEOUT", 30*time.Second),
			ReadTimeout:       getEnvDuration("READ_TIMEOUT", 15*time.Second),
			WriteTimeout:      getEnvDuration("WRITE_TIMEOUT", 15*time.Second),
			IdleTimeout:       getEnvDuration("IDLE_TIMEOUT", 60*time.Second),
			CORSOrigins:       getEnvSlice("CORS_ALLOWED_ORIGINS", []string{"http://localhost:5173", "http://localhost:8081"}),
			CORSMethods:       getEnvSlice("CORS_ALLOWED_METHODS", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"}),
			CORSHeaders:       getEnvSlice("CORS_ALLOWED_HEADERS", []string{"Content-Type", "Authorization"}),
			CORSExposeHeaders: getEnvSlice("CORS_EXPOSE_HEADERS", []string{"Content-Length"}),
			CORSAllowCreds:    getEnvBool("CORS_ALLOW_CREDENTIALS", true),
			CORSMaxAge:        getEnvInt("CORS_MAX_AGE", 3600),
		},
		Database: DatabaseConfig{
			Host:         getEnv("DB_HOST", "localhost"),
			Port:         getEnv("DB_PORT", "5432"),
			Name:         getEnv("DB_NAME", "appdb"),
			User:         getEnv("DB_USER", "appuser"),
			Password:     getEnv("DB_PASSWORD", ""),
			SSLMode:      getEnv("DB_SSLMODE", "disable"),
			MaxOpenConns: getEnvInt("DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns: getEnvInt("DB_MAX_IDLE_CONNS", 5),
			ConnMaxLife:  getEnvDuration("DB_CONN_MAX_LIFETIME", 5*time.Minute),
		},
		JWT: JWTConfig{
			SecretKey:             getEnv("JWT_SECRET", ""),
			ExpirationTime:        getEnvDuration("JWT_EXPIRATION_TIME", 60*time.Minute),
			RefreshExpirationTime: getEnvDuration("JWT_REFRESH_EXPIRATION_TIME", 10080*time.Minute),
			Algorithm:             getEnv("JWT_ALGORITHM", "HS256"),
		},
		Logging: LoggingConfig{
			Enabled:    getEnvBool("LOG_ENABLED", true),
			Level:      getEnv("LOG_LEVEL", "info"),
			Format:     getEnv("LOG_FORMAT", "json"),
			File:       getEnv("LOG_FILE", "app/dev/logs/app.log"),
			MaxSize:    getEnvInt("LOG_MAX_SIZE", 100),
			MaxBackups: getEnvInt("LOG_MAX_BACKUPS", 3),
			MaxAge:     getEnvInt("LOG_MAX_AGE", 28),
		},
		Security: SecurityConfig{
			PasswordMinLength:     getEnvInt("PASSWORD_MIN_LENGTH", 8),
			PasswordUppercase:     getEnvBool("PASSWORD_REQUIRE_UPPERCASE", true),
			PasswordLowercase:     getEnvBool("PASSWORD_REQUIRE_LOWERCASE", true),
			PasswordNumbers:       getEnvBool("PASSWORD_REQUIRE_NUMBERS", true),
			PasswordSpecial:       getEnvBool("PASSWORD_REQUIRE_SPECIAL", true),
			MaxFailedAttempts:     getEnvInt("MAX_FAILED_ATTEMPTS", 5),
			LockoutDuration:       getEnvDuration("LOCKOUT_DURATION", 15*time.Minute),
			LockLevels:            getEnvInt("LOCK_LEVELS", 3),
			LockLevel1Attempts:    getEnvInt("LOCK_LEVEL_1_ATTEMPTS", 3),
			LockLevel1Duration:    getEnvDuration("LOCK_LEVEL_1_DURATION", 5*time.Minute),
			LockLevel2Attempts:    getEnvInt("LOCK_LEVEL_2_ATTEMPTS", 5),
			LockLevel2Duration:    getEnvDuration("LOCK_LEVEL_2_DURATION", 15*time.Minute),
			LockLevel3Attempts:    getEnvInt("LOCK_LEVEL_3_ATTEMPTS", 10),
			LockLevel3Duration:    getEnvDuration("LOCK_LEVEL_3_DURATION", 60*time.Minute),
			LockLevelManualAtmpts: getEnvInt("LOCK_LEVEL_MANUAL_ATTEMPTS", 15),
			RateLimit:             getEnvInt("RATE_LIMIT", 100),
			RateBurst:             getEnvInt("RATE_BURST", 200),
		},
		App: AppConfig{
			Env:     getEnv("APP_ENV", "development"),
			Version: getEnv("APP_VERSION", "1.0.0"),
			Name:    getEnv("APP_NAME", "Open-Generic-Hub"),
		},
		Paths: PathsConfig{
			SchemaDir:     getEnv("SCHEMA_DIR", "database/schema"),
			MigrationsDir: getEnv("MIGRATIONS_DIR", "database/migrations"),
			LogsDir:       getEnv("LOGS_DIR", "logs"),
			ReportsDir:    getEnv("REPORTS_DIR", "reports"),
		},
	}

	return config, nil
}

// GetConfig returns the global configuration (singleton pattern)
func GetConfig() *Config {
	configOnce.Do(func() {
		cfg, err := LoadConfig()
		if err != nil {
			panic(fmt.Sprintf("Failed to load configuration: %v", err))
		}
		globalConfig = cfg
	})
	return globalConfig
}

// GetDatabaseURL returns the PostgreSQL connection string
func (c *Config) GetDatabaseURL() string {
	password := ""
	if c.Database.Password != "" {
		password = ":" + c.Database.Password
	}
	return fmt.Sprintf("postgres://%s%s@%s:%s/%s?sslmode=%s",
		c.Database.User,
		password,
		c.Database.Host,
		c.Database.Port,
		c.Database.Name,
		c.Database.SSLMode,
	)
}

// Helper functions to read environment variables with defaults

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if value := os.Getenv(key); value != "" {
		value = strings.ToLower(strings.TrimSpace(value))
		return value == "true" || value == "yes" || value == "1" || value == "on"
	}
	return fallback
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return time.Duration(intVal) * time.Second
		}
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return fallback
}

func getEnvSlice(key string, fallback []string) []string {
	if value := os.Getenv(key); value != "" {
		parts := strings.Split(value, ",")
		result := make([]string, 0, len(parts))
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if len(trimmed) > 0 {
				result = append(result, trimmed)
			}
		}
		return result
	}
	return fallback
}
