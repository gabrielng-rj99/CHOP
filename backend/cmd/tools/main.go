// Contracts-Manager/backend/cmd/tools/main.go

package main

import (
	"Contracts-Manager/backend/database"
	"Contracts-Manager/backend/store"
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// CreateAdminUser cria um usuário admin com uma senha aleatória.
func main() {
	fmt.Println("Iniciando terminal de ferramentas...")

	// Verifica e inicia o banco principal se necessário
	if err := ensurePostgresRunning("postgres", "5432"); err != nil {
		fmt.Printf("Erro ao iniciar PostgreSQL: %v\n", err)
		return
	}

	db, err := database.ConnectDB()
	if err != nil {
		fmt.Println("Erro ao conectar ao banco de dados:", err)
		return
	}
	defer db.Close()

	userStore := store.NewUserStore(db)

	fmt.Println("=== Ferramentas de Administração ===")
	for {
		fmt.Println("\nEscolha uma função para executar:")
		fmt.Println("1 - Criar usuário admin com senha aleatória")
		fmt.Println("2 - Rodar testes automatizados do projeto com PostgreSQL via Docker Compose")
		fmt.Println("0 - Sair")
		fmt.Print("Opção: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "1":
			fmt.Print("Username do admin (deixe vazio para auto gerar admin-n): ")
			username, _ := reader.ReadString('\n')
			username = strings.TrimSpace(username)
			fmt.Print("Display Name do admin: ")
			displayName, _ := reader.ReadString('\n')
			displayName = strings.TrimSpace(displayName)
			fmt.Print("Role do admin (admin/full_admin): ")
			role, _ := reader.ReadString('\n')
			role = strings.TrimSpace(role)
			if role == "" {
				role = "admin"
			}
			genID, genUsername, genDisplayName, genPassword, err := userStore.CreateAdminUser(username, displayName, role)
			if err != nil {
				fmt.Println("Erro ao criar admin:", err)
			} else {
				fmt.Printf("Usuário admin criado: %s\nDisplay Name: %s\nSenha: %s\nUser ID: %s\n", genUsername, genDisplayName, genPassword, genID)
			}

		case "2":
			RunIntegrationTestsWithDockerPostgres()
		case "0":
			fmt.Println("Saindo...")
			return
		default:
			fmt.Println("Opção inválida.")
		}
	}
}

// ensurePostgresRunning verifica se o container está rodando e saudável.
// Se não estiver, sobe o serviço via docker compose.
func ensurePostgresRunning(service string, port string) error {
	// Primeiro, tenta conectar diretamente para ver se está pronto
	if isPostgresReady("localhost", port) {
		fmt.Printf("✓ PostgreSQL já está rodando na porta %s\n", port)
		return nil
	}

	// Verifica se o container está rodando mas não pronto
	if isContainerRunning(service) {
		fmt.Printf("Container %s está rodando mas não está pronto. Aguardando...\n", service)
		if waitForPostgres("localhost", port, 30*time.Second) {
			fmt.Println("✓ PostgreSQL está pronto!")
			return nil
		}
		return fmt.Errorf("timeout aguardando PostgreSQL ficar pronto")
	}

	// Container não está rodando, então sobe
	fmt.Printf("Banco principal não está rodando. Iniciando serviço '%s'...\n", service)
	if err := runDockerComposeUp(service); err != nil {
		return fmt.Errorf("erro ao subir Docker Compose: %w", err)
	}

	// Aguarda o container ficar pronto
	fmt.Println("Aguardando PostgreSQL iniciar...")
	if !waitForPostgres("localhost", port, 30*time.Second) {
		return fmt.Errorf("PostgreSQL não ficou pronto no tempo esperado")
	}

	fmt.Println("✓ PostgreSQL está pronto!")
	return nil
}

// isContainerRunning verifica se um container específico está rodando
func isContainerRunning(containerName string) bool {
	cmd := exec.Command("docker", "ps", "--filter", fmt.Sprintf("name=%s", containerName), "--format", "{{.Names}}")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) != ""
}

// isPostgresReady tenta conectar ao PostgreSQL usando database/sql
// Isso é mais confiável que pg_isready pois não depende de ferramentas externas
func isPostgresReady(host string, port string) bool {
	dsn := fmt.Sprintf("postgres://postgres:postgres@%s:%s/contracts_manager?sslmode=disable", host, port)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return false
	}
	defer db.Close()

	// Tenta fazer um ping
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = db.PingContext(ctx)
	return err == nil
}

// waitForPostgres aguarda até que o PostgreSQL esteja pronto na porta especificada
func waitForPostgres(host string, port string, maxWaitTime time.Duration) bool {
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

// Sobe o serviço especificado do docker-compose
func runDockerComposeUp(service string) error {
	projectRoot, err := os.Getwd()
	if err != nil {
		return err
	}
	dockerComposePath := filepath.Join(projectRoot, "database", "docker-compose.yml")
	cmd := exec.Command("docker", "compose", "-f", dockerComposePath, "up", "-d", service)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
