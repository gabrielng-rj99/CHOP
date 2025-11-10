package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// runShell executa um comando shell, processa a saída dos testes e retorna erro se houver falhas.
// Também retorna o relatório processado.
func runShell(cmd string) (string, error) {
	command := exec.Command("bash", "-c", cmd)
	var out bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &out
	command.Stderr = &stderr

	err := command.Run()
	output := out.String() + stderr.String()

	var passed, failed, errors []string
	var pkgReports = make(map[string][]string)
	var pkgCoverage = make(map[string]string)

	// Processa a saída SEM printar nada durante a execução
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()

		// Coleta APENAS linhas que indicam falha real
		if strings.HasPrefix(line, "--- FAIL:") {
			failed = append(failed, line)
			errors = append(errors, line)
		}
		// Linhas com mensagens de erro (com indentação, vindo dos testes)
		if strings.HasPrefix(line, "\t") && (strings.Contains(line, "error") || strings.Contains(line, "Error") || strings.Contains(line, "Erro")) {
			errors = append(errors, line)
		}
		if strings.HasPrefix(line, "--- PASS:") {
			passed = append(passed, line)
		}

		// Agrupamento por pacote
		if strings.HasPrefix(line, "ok ") || strings.HasPrefix(line, "FAIL ") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				pkg := parts[1]
				pkgReports[pkg] = append(pkgReports[pkg], line)
				if strings.Contains(line, "coverage:") {
					pkgCoverage[pkg] = line
				}
			}
		}
	}

	// Printa apenas os erros encontrados
	if len(errors) > 0 {
		fmt.Println("\n⚠️  ERROS ENCONTRADOS:")
		fmt.Println("─────────────────────────────────────")
		for _, e := range errors {
			fmt.Println(e)
		}
		fmt.Println("")
	}

	// Relatório final agrupado por pacote
	report := "\n\n===== RELATÓRIO FINAL DE TESTES =====\n\n"
	report += fmt.Sprintf("📊 Total de testes passados: %d\n", len(passed))
	report += fmt.Sprintf("❌ Total de testes falhados: %d\n", len(failed))
	report += "─────────────────────────────────────\n\n"

	report += "📦 RELATÓRIO POR PACOTE:\n"
	for pkg, lines := range pkgReports {
		report += fmt.Sprintf("\n📁 Pacote: %s\n", pkg)
		for _, l := range lines {
			report += "   " + l + "\n"
		}
		if cov, ok := pkgCoverage[pkg]; ok {
			report += "   " + cov + "\n"
		}
	}

	report += "\n─────────────────────────────────────\n"
	report += "❌ TESTES QUE FALHARAM:\n"
	for _, e := range errors {
		report += "   " + e + "\n"
	}

	report += "\n✅ TESTES QUE PASSARAM:\n"
	for _, p := range passed {
		report += "   " + p + "\n"
	}

	return report, err
}
