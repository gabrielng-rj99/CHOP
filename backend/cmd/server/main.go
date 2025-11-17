package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"Contracts-Manager/backend/config"
	"Contracts-Manager/backend/server"

	"gopkg.in/natefinch/lumberjack.v2"
)

func main() {
	// Load configuration from config.ini
	cfg, err := config.LoadConfig("")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

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

	// Print configuration (for debugging)
	if cfg.Application.Env == "development" {
		cfg.PrintConfig()
	}

	// Create server WITHOUT database connection initially
	// Database will be connected/initialized via frontend deployment panel
	var db *sql.DB
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
	fmt.Printf("🚀 %s v%s starting...\n", cfg.Application.Name, cfg.Application.Version)
	fmt.Printf("📡 Server running on http://%s:%s\n", cfg.Server.Host, port)
	fmt.Printf("🗄️  Database will be configured via deployment panel\n")
	fmt.Printf("🔐 Environment: %s\n", cfg.Application.Env)
	fmt.Printf("💡 Open http://%s:%s in browser to initialize\n", cfg.Server.Host, port)

	// Start server
	log.Fatal(httpServer.ListenAndServe())
}

// validateSecrets checks that required secrets are set via environment variables
func validateSecrets(cfg *config.Config) {
	dbPassword := os.Getenv("APP_DATABASE_PASSWORD")
	jwtSecret := os.Getenv("APP_JWT_SECRET_KEY")

	hasErrors := false

	// Check database password
	if dbPassword == "" {
		log.Println("❌ ERROR: APP_DATABASE_PASSWORD is not set")
		log.Println("   Set this environment variable with your database password")
		hasErrors = true
	}

	// Check JWT secret
	if jwtSecret == "" {
		log.Println("❌ ERROR: APP_JWT_SECRET_KEY is not set")
		log.Println("   Set this environment variable with a secure random key")
		log.Println("   Generate with: openssl rand -base64 32")
		hasErrors = true
	}

	if hasErrors {
		log.Println("")
		log.Println("⚠️  SECURITY: Secrets must NEVER be in config.ini")
		log.Println("   They must come from environment variables only:")
		log.Println("")
		log.Println("   Development:  source .env && go run cmd/server/main.go")
		log.Println("   Production:   docker run -e APP_DATABASE_PASSWORD=... -e APP_JWT_SECRET_KEY=...")
		log.Println("   CI/CD:        Use your secrets management system")
		log.Println("")
		log.Fatal("Cannot start server without required secrets")
	}

	if cfg.Application.Env == "production" {
		// Additional warnings for production
		if len(jwtSecret) < 32 {
			log.Println("⚠️  WARNING: JWT secret is less than 32 characters")
			log.Println("   Consider using a longer, more secure secret key")
		}
	}
}
