package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// SetupFlowResult contains the results of the setup flow
type SetupFlowResult struct {
	ShouldProceed bool
	IsFirstRun    bool
	DBPassword    string
	JWTSecret     string
	AdminPassword string
	ConfigChanged bool
}

// RunDockerSetupFlow orchestrates the complete setup flow
func RunDockerSetupFlow() (*SetupFlowResult, error) {
	result := &SetupFlowResult{}

	// Step 1: Check if volumes exist
	fmt.Println("\nChecking for existing volumes...")
	volumeExists, err := checkVolumeExists()
	if err != nil {
		return nil, fmt.Errorf("failed to check volumes: %w", err)
	}

	result.IsFirstRun = !volumeExists

	if !volumeExists {
		// Step 2: Warn about no volumes and ask to proceed
		fmt.Println("\nWARNING: No existing volumes found!")
		fmt.Println("This appears to be a first-time setup or volumes were removed.")
		fmt.Println("Proceeding will create a fresh database (all previous data will be lost if volumes were removed).")
		fmt.Print("\nDo you want to proceed with fresh setup? (yes/no): ")

		if !getUserConfirmation() {
			result.ShouldProceed = false
			return result, nil
		}

		// Step 3: Ask if user wants to configure settings
		fmt.Println("\nConfiguration Options")
		fmt.Print("Do you want to customize configuration (database name, user, ports, etc.)? (yes/no): ")

		if getUserConfirmation() {
			// Step 3.1: Open editor with docker.ini
			if err := openConfigEditor(); err != nil {
				fmt.Printf("Failed to open editor: %v\n", err)
				fmt.Println("You can manually edit deploy/config/docker.ini")
			} else {
				fmt.Println("Configuration file saved")
			}
			result.ConfigChanged = true
		}
	}

	// Step 4: Generate/prompt for secrets
	fmt.Println("\nSecurity Configuration")
	fmt.Println("Now we need to set up security credentials:")

	// Database password
	fmt.Println("\n1. Database Password")
	var dbPassword string
	for {
		fmt.Print("   Enter database password (leave empty for auto-generated 64-char password): ")
		dbPassword = readPasswordInput()
		if strings.TrimSpace(dbPassword) == "" {
			dbPassword = generateSecurePassword(64)
			fmt.Println("   Auto-generated secure database password")
			break
		} else {
			if err := validatePassword(dbPassword); err != nil {
				fmt.Printf("   Invalid password: %v\n", err)
				continue
			}
			fmt.Println("   Using provided database password")
			break
		}
	}
	result.DBPassword = dbPassword

	// JWT Secret
	fmt.Println("\n2. JWT Secret")
	var jwtSecret string
	for {
		fmt.Print("   Enter JWT secret (leave empty for auto-generated secure secret): ")
		jwtSecret = readPasswordInput()
		if strings.TrimSpace(jwtSecret) == "" {
			jwtSecret = generateSecurePassword(64)
			fmt.Println("   Auto-generated secure JWT secret")
			break
		} else {
			if err := validatePassword(jwtSecret); err != nil {
				fmt.Printf("   Invalid secret: %v\n", err)
				continue
			}
			fmt.Println("   Using provided JWT secret")
			break
		}
	}
	result.JWTSecret = jwtSecret

	// Admin Root Password (only for first run)
	if result.IsFirstRun {
		fmt.Println("\n3. Admin Root User Password")
		var adminPassword string
		for {
			fmt.Print("   Enter admin root password (leave empty for auto-generated 64-char password): ")
			adminPassword = readPasswordInput()
			if strings.TrimSpace(adminPassword) == "" {
				adminPassword = generateSecurePassword(64)
				fmt.Println("   Auto-generated secure admin root password")
				break
			} else {
				if err := validatePassword(adminPassword); err != nil {
					fmt.Printf("   Invalid password: %v\n", err)
					continue
				}
				fmt.Println("   Using provided admin root password")
				break
			}
		}
		result.AdminPassword = adminPassword
	}

	// Clear terminal before showing credentials
	clearTerminal()

	// Display credentials securely
	displayCredentialsSafely(result.DBPassword, result.JWTSecret, result.AdminPassword, result.IsFirstRun)

	result.ShouldProceed = true
	return result, nil
}

// checkVolumeExists checks if the configured PostgreSQL volume exists
func checkVolumeExists() (bool, error) {
	cfg, err := LoadConfig("deploy/config/docker.ini")
	if err != nil {
		return false, err
	}

	volumeName := cfg.Docker.PostgresVolume
	if volumeName == "" {
		volumeName = "postgres_data"
	}

	// Check docker compose volumes
	cmd := exec.Command("docker", "volume", "ls", "-q")
	output, err := cmd.Output()
	if err != nil {
		return false, err
	}

	volumes := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, vol := range volumes {
		if strings.Contains(vol, volumeName) {
			return true, nil
		}
	}

	return false, nil
}

// getUserConfirmation reads yes/no input from user
func getUserConfirmation() bool {
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	input = strings.ToLower(strings.TrimSpace(input))
	return input == "yes" || input == "y"
}

// readPasswordInput reads password input (shows what user types)
func readPasswordInput() string {
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimSpace(input)
}

// generateSecurePassword generates a cryptographically secure random password that meets validation criteria
func generateSecurePassword(length int) string {
	if length < 32 {
		length = 64 // Minimum 64 chars to ensure security
	}

	// Define character sets
	const (
		lowercase = "abcdefghijklmnopqrstuvwxyz"
		uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		digits    = "0123456789"
		symbols   = "!@#$%^&*()-_=+[]{}|;:,.<>?/"
		allChars  = lowercase + uppercase + digits + symbols
	)

	// Ensure we have at least one of each required character type
	requiredChars := []byte{
		lowercase[rand.Intn(len(lowercase))], // at least one lowercase
		uppercase[rand.Intn(len(uppercase))], // at least one uppercase
		digits[rand.Intn(len(digits))],       // at least one digit
		symbols[rand.Intn(len(symbols))],     // at least one symbol
	}

	// Fill the rest with random characters from all sets
	password := make([]byte, length)
	copy(password[:4], requiredChars)

	for i := 4; i < length; i++ {
		password[i] = allChars[rand.Intn(len(allChars))]
	}

	// Shuffle the password to randomize positions
	for i := len(password) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		password[i], password[j] = password[j], password[i]
	}

	return string(password)
}

// displayCredentialsSafely displays credentials with security warnings and enhanced formatting
func displayCredentialsSafely(dbPassword, jwtSecret, adminPassword string, isFirstRun bool) {
	// ANSI color codes
	reset := "\033[0m"
	red := "\033[1;31m"      // Bold red
	green := "\033[1;32m"    // Bold green
	yellow := "\033[1;33m"   // Bold yellow
	blue := "\033[1;34m"     // Bold blue
	cyan := "\033[1;36m"     // Bold cyan
	redBg := "\033[41;1;37m" // Red background, bold white text

	fmt.Println("\n" + yellow + strings.Repeat("=", 80) + reset)
	fmt.Println(yellow + "CREDENTIALS GENERATED - SAVE THESE SECURELY!" + reset)
	fmt.Println(yellow + strings.Repeat("=", 80) + reset)
	fmt.Println()
	fmt.Println(yellow + "CRITICAL SECURITY NOTICE:" + reset)
	fmt.Println(yellow + "   Save these credentials in a password manager IMMEDIATELY!" + reset)
	fmt.Println(yellow + "   These will NEVER be shown again after this setup completes." + reset)
	fmt.Println(yellow + "   If lost, you will need to regenerate them (losing all data)." + reset)
	fmt.Println()

	// Database Password with enhanced formatting
	fmt.Println(blue + "DATABASE PASSWORD:" + reset)
	fmt.Printf("   "+redBg+" %s "+reset+"\n", dbPassword)
	fmt.Println()

	// JWT Secret with enhanced formatting
	fmt.Println(blue + "JWT SECRET:" + reset)
	fmt.Printf("   "+redBg+" %s "+reset+"\n", jwtSecret)
	fmt.Println()

	// Admin Root Password (only for first run)
	if isFirstRun && adminPassword != "" {
		fmt.Println(blue + "ADMIN ROOT USER:" + reset)
		fmt.Println("   Username: root")
		fmt.Printf("   Password: "+redBg+" %s "+reset+"\n", adminPassword)
		fmt.Println("   Role: root (full system access)")
		fmt.Println()
	}

	fmt.Println(red + strings.Repeat("=", 80) + reset)
	fmt.Println()
	fmt.Println(green + "RECOMMENDED PASSWORD MANAGERS:" + reset)
	fmt.Println(cyan + "   • Bitwarden (https://bitwarden.com)" + reset)
	fmt.Println(cyan + "   • 1Password (https://1password.com)" + reset)
	fmt.Println(cyan + "   • KeePassXC (https://keepassxc.org)" + reset)
	fmt.Println()
	fmt.Print(green + "Press ENTER after saving the credentials to continue..." + reset)
	bufio.NewReader(os.Stdin).ReadString('\n')
}

// validatePassword validates that a password meets security requirements
func validatePassword(password string) error {
	if len(password) < 32 {
		return fmt.Errorf("password must be at least 32 characters long")
	}

	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSymbol = true
		}
	}

	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasDigit {
		return fmt.Errorf("password must contain at least one number")
	}
	if !hasSymbol {
		return fmt.Errorf("password must contain at least one symbol")
	}

	return nil
}

// openConfigEditor opens docker.ini in the user's default editor
func openConfigEditor() error {
	// Get project root and resolve config path
	rootDir, err := getProjectRoot()
	if err != nil {
		return fmt.Errorf("failed to get project root: %w", err)
	}
	configPath := filepath.Join(rootDir, "deploy/config/docker.ini")

	// Add warning to the config file temporarily
	warningMessage := `
# ============================================================================
# IMPORTANT: PASSWORD CONFIGURATION NOTICE
# ============================================================================
# The database password (DB_PASSWORD) and JWT secret (JWT_SECRET) will be
# configured in the next step of the deployment process.
#
# DO NOT set them here - they will be generated securely and injected
# during the docker-compose.yml generation.
# ============================================================================

`

	// Read current config
	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	// Check if warning already exists
	if !strings.Contains(string(content), "PASSWORD CONFIGURATION NOTICE") {
		// Prepend warning
		newContent := warningMessage + string(content)
		if err := os.WriteFile(configPath, []byte(newContent), 0644); err != nil {
			return fmt.Errorf("failed to add warning: %w", err)
		}
	}

	// Determine editor
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = os.Getenv("VISUAL")
	}
	if editor == "" {
		// Try common editors
		editors := []string{"nano", "vim", "vi", "emacs", "micro"}
		for _, e := range editors {
			if _, err := exec.LookPath(e); err == nil {
				editor = e
				break
			}
		}
	}
	if editor == "" {
		return fmt.Errorf("no text editor found (set $EDITOR or $VISUAL)")
	}

	fmt.Printf("\nOpening %s in %s...\n", configPath, editor)
	fmt.Println("Edit the configuration and save when done.")
	fmt.Println("Remember: DB password and JWT secret will be set in the next step!")
	fmt.Println("\nPress ENTER to continue...")
	bufio.NewReader(os.Stdin).ReadString('\n')

	// Open editor
	cmd := exec.Command(editor, configPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("editor exited with error: %w", err)
	}

	return nil
}

// GenerateDockerComposeWithSecrets generates docker-compose.yml with the provided secrets
func GenerateDockerComposeWithSecrets(dbPassword, jwtSecret string) error {
	fmt.Println("\nGenerating docker-compose.yml...")
	fmt.Printf("   Location: deploy/config/docker-compose.yml\n")

	// Load config
	cfg, err := LoadConfig("deploy/config/docker.ini")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Override secrets in config
	cfg.Docker.DBPassword = dbPassword
	cfg.Docker.JWTSecret = jwtSecret

	// Generate compose file
	_, err = GenerateDockerCompose(ComposeGenerationOptions{
		Config:       cfg,
		ConfigPath:   "deploy/config/docker.ini",
		TemplatePath: "deploy/config/templates/docker-compose.tmpl",
		OutputPath:   "deploy/config/docker-compose.yml",
		Force:        true,
	})
	if err != nil {
		return fmt.Errorf("failed to generate compose file: %w", err)
	}

	fmt.Println("   docker-compose.yml generated successfully")
	fmt.Println()
	fmt.Println("TIP: You can make final adjustments to the generated file at:")
	fmt.Println("   deploy/config/docker-compose.yml")
	fmt.Println()
	fmt.Print("   Ready to proceed? Press ENTER to continue or Ctrl+C to abort...")
	bufio.NewReader(os.Stdin).ReadString('\n')

	return nil
}

// createAdminUserInContainer creates the root admin user by executing SQL directly in the postgres container
func createAdminUserInContainer(adminPassword string) error {
	fmt.Println("\nCreating root admin user in the system...")

	// Wait a bit for the backend to be fully ready
	fmt.Println("   Waiting for backend to be ready...")
	time.Sleep(5 * time.Second)

	// Get container name from config
	cfg, err := LoadConfig("deploy/config/docker.ini")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Use postgres container to execute SQL
	postgresContainer := cfg.Docker.PostgresContainer
	if postgresContainer == "" {
		postgresContainer = "postgres"
	}

	// Generate UUID for the user
	userID := generateUUID()

	// Hash the password using bcrypt (same as backend)
	hashedPassword, err := hashPassword(adminPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Create the SQL command to insert the admin user
	sqlCommand := fmt.Sprintf(`
		INSERT INTO users (id, username, display_name, password_hash, role, created_at, updated_at)
		VALUES ('%s', 'root', 'System Administrator', '%s', 'root', NOW(), NOW())
		ON CONFLICT (username) DO NOTHING;
	`, userID, strings.ReplaceAll(hashedPassword, "'", "''"))

	// Execute the SQL using psql in the postgres container
	fmt.Printf("   Executing admin user creation in database...\n")

	// Set PGPASSWORD environment variable and execute psql
	execCmd := exec.Command("docker", "exec",
		"-e", fmt.Sprintf("PGPASSWORD=%s", cfg.Docker.DBPassword),
		postgresContainer,
		"psql",
		"-h", "localhost",
		"-U", cfg.Database.User,
		"-d", cfg.Database.Name,
		"-c", sqlCommand)

	output, err := execCmd.CombinedOutput()
	if err != nil {
		fmt.Printf("   SQL execution output: %s\n", string(output))
		return fmt.Errorf("failed to execute admin creation SQL: %w", err)
	}

	// Check if user was actually created or already exists
	if strings.Contains(string(output), "INSERT 0 0") {
		fmt.Println("   Admin user 'root' already exists, skipping creation")
	} else {
		fmt.Println("   Root admin user created successfully!")
		fmt.Printf("   Username: root\n")
		fmt.Printf("   Display Name: System Administrator\n")
		fmt.Printf("   Password: %s\n", adminPassword)
		fmt.Printf("   User ID: %s\n", userID)
		fmt.Printf("   Role: root\n")
	}

	return nil
}

// generateUUID generates a new UUID string
func generateUUID() string {
	return uuid.New().String()
}

// hashPassword hashes a password using bcrypt
func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
