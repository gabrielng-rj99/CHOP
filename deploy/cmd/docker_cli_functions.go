package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// isContainerRunning checks if a specific container is running.
func isContainerRunning(containerName string) bool {
	cmd := exec.Command("docker", "ps", "--format", "{{.Names}}")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == containerName {
			return true
		}
	}

	return false
}

// waitForPostgresReady waits for PostgreSQL to be ready on the specified port.
func waitForPostgresReady(host string, port string, maxWaitTime time.Duration) bool {
	start := time.Now()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		if isPostgresReady(host, port) {
			return true
		}
		if time.Since(start) > maxWaitTime {
			return false
		}
		<-ticker.C
	}
}

// isPostgresReady attempts to connect to PostgreSQL.
func isPostgresReady(host string, port string) bool {
	dbname := "contracts_manager"
	if port == "65432" {
		dbname = "contracts_manager_test"
	}
	dsn := fmt.Sprintf("postgres://postgres:postgres@%s:%s/%s?sslmode=disable", host, port, dbname)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return false
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = db.PingContext(ctx)
	return err == nil
}

// getDockerComposeCommand returns the docker compose command to use.
// It tries "docker compose" first (modern) and falls back to "docker-compose" (legacy).
func getDockerComposeCommand() ([]string, error) {
	// Try modern "docker compose" first
	cmd := exec.Command("docker", "compose", "version")
	if err := cmd.Run(); err == nil {
		return []string{"docker", "compose"}, nil
	}

	// Fall back to legacy "docker-compose"
	cmd = exec.Command("docker-compose", "--version")
	if err := cmd.Run(); err == nil {
		return []string{"docker-compose"}, nil
	}

	return nil, fmt.Errorf("neither 'docker compose' nor 'docker-compose' found in PATH")
}

// runDockerCompose executes docker compose ensuring the configuration file exists.
func runDockerCompose(args ...string) error {
	composeCmd, err := getDockerComposeCommand()
	if err != nil {
		return err
	}

	composePath, _, err := ensureDockerComposePrepared()
	if err != nil {
		return err
	}

	finalArgs := append(composeCmd, ensureComposeFileArg(args, composePath)...)
	cmd := exec.Command(finalArgs[0], finalArgs[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Dir = filepath.Dir(composePath)
	return cmd.Run()
}

func ensureComposeFileArg(args []string, composePath string) []string {
	for i := 0; i < len(args); i++ {
		if args[i] == "-f" || args[i] == "--file" {
			return args
		}
	}
	result := make([]string, 0, len(args)+2)
	result = append(result, "-f", composePath)
	result = append(result, args...)
	return result
}

// runDockerComposeDownWithVolumes brings down and removes volumes of a specific service.
func runDockerComposeDownWithVolumes(service string) error {
	if err := runDockerCompose("rm", "-s", "-f", service); err != nil {
		return err
	}

	cfg, _, _, _, err := loadDockerArtifacts()
	if err != nil {
		return err
	}

	volumeName := ""
	switch service {
	case "postgres":
		volumeName = pick(cfg.Docker.PostgresVolume, defaultPostgresVolume)
	case "postgres_test":
		volumeName = pick(cfg.Docker.PostgresVolume, defaultPostgresVolume) + "_test"
	}

	if strings.TrimSpace(volumeName) == "" {
		return nil
	}

	volumeCmd := exec.Command("docker", "volume", "rm", "-f", volumeName)
	volumeCmd.Stdout = os.Stdout
	volumeCmd.Stderr = os.Stderr
	_ = volumeCmd.Run()

	return nil
}
