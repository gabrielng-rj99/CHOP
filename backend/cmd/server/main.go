package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"Open-Generic-Hub/backend/config"
	"Open-Generic-Hub/backend/database"
	"Open-Generic-Hub/backend/server"

	"gopkg.in/natefinch/lumberjack.v2"
)

func main() {
	// Load configuration from environment variables
	cfg := config.GetConfig()

	// Validate required secrets are set
	validateSecrets(cfg)

	// Configure logging based on config
	if cfg.Logging.Enabled {
		logFile := &lumberjack.Logger{
			Filename:   cfg.Logging.File,
			MaxSize:    cfg.Logging.MaxSize,    // megabytes
			MaxBackups: cfg.Logging.MaxBackups, // quantos arquivos antigos manter
			MaxAge:     cfg.Logging.MaxAge,     // dias
			Compress:   true,                   // comprimir arquivos antigos
		}
		log.SetOutput(logFile)
	}

	// Try to connect to database automatically with retry logic
	var db *sql.DB
	var err error
	maxRetries := 10
	retryDelay := time.Second

	log.Printf("🔄 Attempting to connect to database...\n")
	for i := 0; i < maxRetries; i++ {
		db, err = database.ConnectDB()
		if err == nil {
			log.Printf("✅ Database connected successfully\n")
			break
		}

		if i < maxRetries-1 {
			log.Printf("⏳ Database connection attempt %d/%d failed: %v. Retrying in %v...\n", i+1, maxRetries, err, retryDelay)
			time.Sleep(retryDelay)
			retryDelay *= 2 // Exponential backoff
		} else {
			log.Printf("⚠️  WARNING: Could not connect to database after %d attempts: %v\n", maxRetries, err)
			log.Printf("📋 Server will start but endpoints requiring database will return 503\n")
			log.Printf("💡 Initialize database via /api/initialize/database endpoint\n")
			db = nil
		}
	}

	srv := server.NewServer(db)
	srv.SetupRoutes()

	// Get port from config (can be overridden by PORT env var for testing)
	port := os.Getenv("PORT")
	if port == "" {
		port = cfg.Server.Port
	}

	// Setup server with timeouts from config
	httpServer := &http.Server{
		Addr:         ":" + port,
		Handler:      http.DefaultServeMux,
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(cfg.Server.IdleTimeout) * time.Second,
	}

	// Log server startup
	fmt.Printf("🚀 %s v%s starting...\n", cfg.App.Name, cfg.App.Version)
	fmt.Printf("📡 Server running on http://%s:%s\n", cfg.Server.Host, port)
	if db != nil {
		fmt.Printf("🗄️  Database: Connected\n")
	} else {
		fmt.Printf("🗄️  Database: Not connected (initialize via API)\n")
	}
	fmt.Printf("🔐 Environment: %s\n", cfg.App.Env)

	// Start server
	log.Fatal(httpServer.ListenAndServe())
}

// validateSecrets checks that required secrets are set via environment variables
func validateSecrets(cfg *config.Config) {
	dbPassword := os.Getenv("DB_PASSWORD")
	jwtSecret := os.Getenv("JWT_SECRET")

	hasErrors := false

	// Check database password (optional in development)
	if dbPassword == "" && cfg.App.Env == "production" {
		log.Println("❌ ERROR: DB_PASSWORD is not set")
		log.Println("   Set this environment variable with your database password")
		hasErrors = true
	}

	// Check JWT secret
	if jwtSecret == "" {
		log.Println("❌ ERROR: JWT_SECRET is not set")
		log.Println("   Set this environment variable with a secure random key")
		log.Println("   Generate with: openssl rand -base64 32")
		hasErrors = true
	}

	if hasErrors {
		log.Println("")
		log.Println("⚠️  SECURITY: Secrets must NEVER be in config.ini")
		log.Println("   They must come from environment variables only:")
		log.Println("")
		log.Println("   Development:  export JWT_SECRET=... && go run cmd/server/main.go")
		log.Println("   Production:   docker run -e DB_PASSWORD=... -e JWT_SECRET=...")
		log.Println("   CI/CD:        Use your secrets management system")
		log.Println("")
		log.Fatal("Cannot start server without required secrets")
	}

	if cfg.App.Env == "production" {
		// Additional warnings for production
		if len(jwtSecret) < 32 {
			log.Println("⚠️  WARNING: JWT secret is less than 32 characters")
			log.Println("   Consider using a longer, more secure secret key")
		}
	}
}
