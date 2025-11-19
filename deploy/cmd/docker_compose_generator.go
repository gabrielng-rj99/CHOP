package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	defaultDockerConfigPath  = "deploy/config/docker.ini"
	defaultComposeTemplate   = "deploy/config/templates/docker-compose.tmpl"
	defaultComposeOutputPath = "deploy/config/docker-compose.yml"

	defaultBackendHostPort   = "3000"
	defaultFrontendHostPort  = "8081"
	defaultFrontendContPort  = "80"
	defaultPostgresPort      = "5432"
	defaultPostgresContainer = "postgres"
	defaultBackendContainer  = "backend"
	defaultFrontendContainer = "frontend"
	defaultPostgresVolume    = "postgres_data"
	composePanelContentWidth = 74

	defaultJWTSecret          = "change_me_in_production_min_32_chars"
	defaultJWTAlgorithm       = "HS256"
	defaultJWTExpiration      = 60
	defaultJWTRefreshDuration = 10080
)

var composePlaceholderPattern = regexp.MustCompile(`\{\{([A-Z0-9_]+)\}\}`)

// ComposeGenerationOptions configures how docker-compose.yml is produced.
type ComposeGenerationOptions struct {
	Config       *Config // Optional: if provided, uses this config instead of loading from file
	ConfigPath   string
	TemplatePath string
	OutputPath   string
	Force        bool
}

// GenerateDockerCompose renders docker-compose.yml from docker.ini and template data.
func GenerateDockerCompose(opts ComposeGenerationOptions) (string, error) {
	rootDir, err := getProjectRoot()
	if err != nil {
		return "", fmt.Errorf("unable to determine project root: %w", err)
	}

	var cfg *Config
	if opts.Config != nil {
		cfg = opts.Config
	} else {
		cfg, err = LoadConfig(resolvePath(rootDir, pick(opts.ConfigPath, defaultDockerConfigPath)))
		if err != nil {
			return "", fmt.Errorf("failed to load docker config: %w", err)
		}
	}

	templatePath := resolvePath(rootDir, pick(opts.TemplatePath, defaultComposeTemplate))
	templateBytes, err := os.ReadFile(templatePath)
	if err != nil {
		return "", fmt.Errorf("failed to read template %s: %w", templatePath, err)
	}

	templateData := buildComposeTemplateData(cfg)
	rendered, err := renderTemplate(string(templateBytes), templateData)
	if err != nil {
		return "", err
	}

	outputPath := resolvePath(rootDir, pick(opts.OutputPath, cfg.Docker.ComposeFile, defaultComposeOutputPath))
	if err := ensureOutputWritable(outputPath, opts.Force); err != nil {
		return "", err
	}

	if err := os.WriteFile(outputPath, []byte(rendered), 0o644); err != nil {
		return "", fmt.Errorf("failed to write compose file %s: %w", outputPath, err)
	}

	return outputPath, nil
}

// ensureDockerComposePrepared guarantees docker-compose.yml exists and is up to date.
// When regeneration is needed it shows a confirmation panel before writing the file.
func ensureDockerComposePrepared() (string, *Config, error) {
	cfg, cfgPath, templatePath, outputPath, err := loadDockerArtifacts()
	if err != nil {
		return "", nil, err
	}

	needsGeneration, reason, err := dockerComposeNeedsGeneration(cfgPath, templatePath, outputPath)
	if err != nil {
		return "", nil, err
	}

	if needsGeneration {
		displayDockerConfigPanel(cfg, templatePath, outputPath, reason)
		if !confirmAction("Type 'yes' to generate docker-compose.yml with the settings above: ") {
			return "", nil, fmt.Errorf("docker compose generation cancelled by user")
		}

		if _, err := GenerateDockerCompose(ComposeGenerationOptions{
			ConfigPath:   cfgPath,
			TemplatePath: templatePath,
			OutputPath:   outputPath,
			Force:        true,
		}); err != nil {
			return "", nil, fmt.Errorf("failed to generate docker compose: %w", err)
		}
		printSuccess(fmt.Sprintf("Docker Compose written to %s", outputPath))
	}

	return outputPath, cfg, nil
}

func renderTemplate(tmpl string, data map[string]string) (string, error) {
	if missing := missingPlaceholders(tmpl, data); len(missing) > 0 {
		return "", fmt.Errorf("template placeholders missing values: %s", strings.Join(missing, ", "))
	}

	result := composePlaceholderPattern.ReplaceAllStringFunc(tmpl, func(match string) string {
		key := composePlaceholderPattern.FindStringSubmatch(match)[1]
		return data[key]
	})

	return result, nil
}

func ensureOutputWritable(path string, force bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create directory for %s: %w", path, err)
	}

	_, err := os.Stat(path)
	switch {
	case err == nil && !force:
		return fmt.Errorf("compose file already exists at %s (set Force to overwrite)", path)
	case err == nil && force:
		return nil
	case errors.Is(err, os.ErrNotExist):
		return nil
	default:
		return fmt.Errorf("failed to inspect %s: %w", path, err)
	}
}

func buildComposeTemplateData(cfg *Config) map[string]string {
	backendHostPort := pick(cfg.Docker.BackendPort, cfg.Server.Port, defaultBackendHostPort)
	backendContPort := pick(cfg.Docker.BackendContainerPort, cfg.Server.Port, defaultBackendHostPort)

	frontendHostPort := pick(cfg.Docker.FrontendPort, defaultFrontendHostPort)
	frontendContPort := pick(cfg.Docker.FrontendContainerPort, defaultFrontendContPort)

	postgresHostPort := pick(cfg.Docker.PostgresPort, cfg.Database.Port, defaultPostgresPort)
	postgresContPort := defaultPostgresPort

	return map[string]string{
		"VARIABLE":                    "VARIABLE",
		"NETWORK_NAME":                pick(cfg.Docker.NetworkName, "opengeneric-network"),
		"POSTGRES_CONTAINER":          pick(cfg.Docker.PostgresContainer, cfg.Database.ContainerName, defaultPostgresContainer),
		"POSTGRES_VOLUME":             pick(cfg.Docker.PostgresVolume, defaultPostgresVolume),
		"BACKEND_CONTAINER":           pick(cfg.Docker.BackendContainer, defaultBackendContainer),
		"FRONTEND_CONTAINER":          pick(cfg.Docker.FrontendContainer, defaultFrontendContainer),
		"BACKEND_CONTAINER_PORT":      backendContPort,
		"BACKEND_HOST_PORT":           backendHostPort,
		"FRONTEND_CONTAINER_PORT":     frontendContPort,
		"FRONTEND_HOST_PORT":          frontendHostPort,
		"DB_NAME":                     pick(cfg.Docker.DBName, cfg.Database.Name, "contracts_manager"),
		"DB_USER":                     pick(cfg.Docker.DBUser, cfg.Database.User, "postgres"),
		"DB_PASSWORD":                 pick(cfg.Docker.DBPassword, cfg.Database.Password, "postgres"),
		"DB_PORT":                     pick(cfg.Docker.DBPort, cfg.Database.Port, defaultPostgresPort),
		"DB_SSLMODE":                  pick(cfg.Docker.DBSSLMode, cfg.Database.SSLMode, "disable"),
		"JWT_SECRET":                  pick(cfg.Docker.JWTSecret, defaultJWTSecret),
		"JWT_ALGORITHM":               pick(cfg.Docker.JWTAlgorithm, cfg.JWT.Algorithm, defaultJWTAlgorithm),
		"JWT_EXPIRATION_TIME":         intStringOrDefault(cfg.Docker.JWTExpirationTime, defaultJWTExpiration),
		"JWT_REFRESH_EXPIRATION_TIME": intStringOrDefault(cfg.Docker.JWTRefreshExpirationTime, defaultJWTRefreshDuration),
		"POSTGRES_PORTS":              portSection(cfg.Docker.ExposePostgresPort, postgresHostPort, postgresContPort),
		"BACKEND_PORTS":               portSection(cfg.Docker.ExposeBackendPort, backendHostPort, backendContPort),
		"FRONTEND_PORTS":              portSection(cfg.Docker.ExposeFrontendPort, frontendHostPort, frontendContPort),
	}
}

func missingPlaceholders(tmpl string, data map[string]string) []string {
	matches := composePlaceholderPattern.FindAllStringSubmatch(tmpl, -1)
	if len(matches) == 0 {
		return nil
	}

	missing := map[string]struct{}{}
	for _, match := range matches {
		key := match[1]
		if _, ok := data[key]; !ok {
			missing[key] = struct{}{}
		}
	}

	if len(missing) == 0 {
		return nil
	}

	keys := make([]string, 0, len(missing))
	for key := range missing {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	return keys
}

func portSection(enabled bool, host, container string) string {
	if !enabled {
		return ""
	}

	return fmt.Sprintf("        ports:\n            - \"%s:%s\"\n", pick(host, container), pick(container, host))
}

func pick(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func resolvePath(root, target string) string {
	if filepath.IsAbs(target) {
		return target
	}
	return filepath.Join(root, target)
}

func intStringOrDefault(value int, fallback int) string {
	if value <= 0 {
		return strconv.Itoa(fallback)
	}
	return strconv.Itoa(value)
}

func loadDockerArtifacts() (*Config, string, string, string, error) {
	rootDir, err := getProjectRoot()
	if err != nil {
		return nil, "", "", "", err
	}

	configPath := filepath.Join(rootDir, defaultDockerConfigPath)
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return nil, "", "", "", fmt.Errorf("failed to load %s: %w", configPath, err)
	}

	templatePath := filepath.Join(rootDir, defaultComposeTemplate)

	outputPath := cfg.Docker.ComposeFile
	if strings.TrimSpace(outputPath) == "" {
		outputPath = defaultComposeOutputPath
	}
	if !filepath.IsAbs(outputPath) {
		outputPath = filepath.Join(rootDir, outputPath)
	}

	return cfg, configPath, templatePath, outputPath, nil
}

func dockerComposeNeedsGeneration(configPath, templatePath, outputPath string) (bool, string, error) {
	outputInfo, err := os.Stat(outputPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, "docker-compose.yml not found", nil
		}
		return true, "", fmt.Errorf("failed to inspect compose file %s: %w", outputPath, err)
	}

	templateInfo, err := os.Stat(templatePath)
	if err != nil {
		return true, "", fmt.Errorf("failed to inspect template %s: %w", templatePath, err)
	}
	if templateInfo.ModTime().After(outputInfo.ModTime()) {
		return true, "Template file was modified after docker-compose.yml", nil
	}

	configInfo, err := os.Stat(configPath)
	if err == nil && configInfo.ModTime().After(outputInfo.ModTime()) {
		return true, "docker.ini was modified after docker-compose.yml", nil
	}

	return false, "", nil
}

func displayDockerConfigPanel(cfg *Config, templatePath, outputPath, reason string) {
	fmt.Println()
	fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                🐳 DOCKER COMPOSE CONFIGURATION REVIEW 🐳                  ║")
	fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
	printPanelLine(fmt.Sprintf("Reason   : %s", pick(reason, "Regeneration required")))
	printPanelLine(fmt.Sprintf("Template : %s", templatePath))
	printPanelLine(fmt.Sprintf("Output   : %s", outputPath))
	printPanelLine(fmt.Sprintf("Network  : %s", pick(cfg.Docker.NetworkName, "opengeneric-network")))
	fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
	printPanelLine(fmt.Sprintf("Postgres : container=%s | host-port=%s | expose=%t",
		pick(cfg.Docker.PostgresContainer, defaultPostgresContainer),
		pick(cfg.Docker.PostgresPort, defaultPostgresPort),
		cfg.Docker.ExposePostgresPort))
	printPanelLine(fmt.Sprintf("Backend  : container=%s | host-port=%s | expose=%t",
		pick(cfg.Docker.BackendContainer, defaultBackendContainer),
		pick(cfg.Docker.BackendPort, defaultBackendHostPort),
		cfg.Docker.ExposeBackendPort))
	printPanelLine(fmt.Sprintf("Frontend : container=%s | host-port=%s | expose=%t",
		pick(cfg.Docker.FrontendContainer, defaultFrontendContainer),
		pick(cfg.Docker.FrontendPort, defaultFrontendHostPort),
		cfg.Docker.ExposeFrontendPort))
	fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
	printPanelLine(fmt.Sprintf("Database user=%s | name=%s | port=%s",
		pick(cfg.Database.User, "postgres"),
		pick(cfg.Database.Name, "appdb"),
		pick(cfg.Database.Port, defaultPostgresPort)))
	printPanelLine(fmt.Sprintf("JWT algo=%s | exp=%s | refresh=%s",
		pick(cfg.Docker.JWTAlgorithm, defaultJWTAlgorithm),
		pick(strconv.Itoa(cfg.Docker.JWTExpirationTime), strconv.Itoa(defaultJWTExpiration)),
		pick(strconv.Itoa(cfg.Docker.JWTRefreshExpirationTime), strconv.Itoa(defaultJWTRefreshDuration))))
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")
}

func printPanelLine(content string) {
	fmt.Printf("║ %-*s ║\n", composePanelContentWidth, padOrTrim(content, composePanelContentWidth))
}

func padOrTrim(text string, width int) string {
	runes := []rune(text)
	if len(runes) <= width {
		return text + strings.Repeat(" ", width-len(runes))
	}
	if width <= 3 {
		return string(runes[:width])
	}
	return string(runes[:width-3]) + "..."
}
