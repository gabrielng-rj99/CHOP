package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Flag global para controlar clearTerminal
var skipClearTerminal bool

// isContainerRunning verifica se um container específico está rodando
func isContainerRunning(containerName string) bool {
	cmd := exec.Command("docker", "ps", "--format", "{{.Names}}")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// Split output by newlines and check for exact match
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == containerName {
			return true
		}
	}

	return false
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

// getDockerComposePath retorna o caminho do docker compose.yml
func getDockerComposePath() (string, error) {
	projectRoot, err := getProjectRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(projectRoot, "database", "docker-compose.yml"), nil
}

// runDockerComposeUp sobe o serviço especificado do docker compose
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

// runDockerComposeDown derruba todos os serviços do docker compose
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

// runDockerComposeStop para o serviço especificado do docker compose
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

	// Para remover apenas um serviço específico com volumes, precisamos:
	// 1. Parar o container
	// 2. Remover o container
	// 3. Remover o volume associado

	// Parar e remover o container
	stopCmd := exec.Command("docker", "compose", "-f", dockerComposePath, "rm", "-s", "-f", service)
	stopCmd.Stdout = os.Stdout
	stopCmd.Stderr = os.Stderr
	if err := stopCmd.Run(); err != nil {
		return err
	}

	// Remover o volume específico do serviço
	volumeName := ""
	if service == "postgres_test" {
		volumeName = "database_postgres_test_data"
	} else if service == "postgres" {
		volumeName = "database_postgres_data"
	}

	if volumeName != "" {
		volumeCmd := exec.Command("docker", "volume", "rm", "-f", volumeName)
		volumeCmd.Stdout = os.Stdout
		volumeCmd.Stderr = os.Stderr
		// Ignora erro se o volume não existir
		_ = volumeCmd.Run()
	}

	return nil
}

// runShell executa um comando shell com saída direta no terminal
func runShell(cmd string) error {
	command := exec.Command("bash", "-c", cmd)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.Env = os.Environ()
	return command.Run()
}

// clearTerminal limpa o terminal, respeitando a flag skipClearTerminal
func clearTerminal() {
	if skipClearTerminal {
		return
	}

	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "cls")
	default: // linux, darwin, etc
		cmd = exec.Command("clear")
	}

	cmd.Stdout = os.Stdout
	cmd.Run()
}

// simulateEnterForNextFunction simula um ENTER para funções que esperam input do usuário
func simulateEnterForNextFunction(f func()) {
	originalStdin := os.Stdin
	r, w, _ := os.Pipe()
	w.Write([]byte("\n"))
	w.Close()
	os.Stdin = r
	skipClearTerminal = true
	f()
	skipClearTerminal = false
	os.Stdin = originalStdin
}
