package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// isContainerRunning verifica se um container específico está rodando
func isContainerRunning(containerName string) bool {
	cmd := exec.Command("docker", "ps", "--filter", fmt.Sprintf("name=%s", containerName), "--format", "{{.Names}}")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return len(output) > 0
}

// waitForPostgresReady aguarda até que o PostgreSQL esteja pronto na porta especificada
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

// isPostgresReady tenta conectar ao PostgreSQL usando database/sql
func isPostgresReady(host string, port string) bool {
	// Usa contracts_manager_test para porta de teste, contracts_manager para principal
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

// getProjectRoot retorna o diretório raiz do projeto
func getProjectRoot() (string, error) {
	return os.Getwd()
}

// getDockerComposePath retorna o caminho do docker-compose.yml
func getDockerComposePath() (string, error) {
	projectRoot, err := getProjectRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(projectRoot, "database", "docker-compose.yml"), nil
}

// runDockerComposeUp sobe o serviço especificado do docker-compose
func runDockerComposeUp(service string) error {
	dockerComposePath, err := getDockerComposePath()
	if err != nil {
		return err
	}
	cmd := exec.Command("docker", "compose", "-f", dockerComposePath, "up", "-d", service)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runDockerComposeDown derruba todos os serviços do docker-compose
func runDockerComposeDown() error {
	dockerComposePath, err := getDockerComposePath()
	if err != nil {
		return err
	}
	cmd := exec.Command("docker", "compose", "-f", dockerComposePath, "down")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runDockerComposeStop para o serviço especificado do docker-compose
func runDockerComposeStop(service string) error {
	dockerComposePath, err := getDockerComposePath()
	if err != nil {
		return err
	}
	cmd := exec.Command("docker", "compose", "-f", dockerComposePath, "stop", service)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runDockerComposeDownWithVolumes derruba e remove volumes do serviço especificado
func runDockerComposeDownWithVolumes(service string) error {
	dockerComposePath, err := getDockerComposePath()
	if err != nil {
		return err
	}
	cmd := exec.Command("docker", "compose", "-f", dockerComposePath, "down", "-v")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
