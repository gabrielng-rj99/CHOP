package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// RunIntegrationTestsWithDockerPostgres executa todos os testes do projeto usando PostgreSQL via Docker Compose
func RunIntegrationTestsWithDockerPostgres() {
	clearTerminal()
	fmt.Println("\n=== Testes de Integração com PostgreSQL (porta 65432) ===")

	projectRoot, err := os.Getwd()
	if err != nil {
		fmt.Println("❌ Erro ao determinar raiz do projeto:", err)
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}

	// Verifica se o container de teste já está rodando
	if !isContainerRunning("contract_manager_postgres_test") {
		fmt.Println("❌ O banco de testes NÃO está inicializado!")
		fmt.Println("Sugestão: Rode a opção 21 antes para inicializar o banco de testes.")
		fmt.Print("Pressione ENTER para voltar ao menu...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}

	fmt.Println("✓ Banco de testes está rodando!")

	// Aguarda o banco ficar pronto
	fmt.Println("⏳ Aguardando postgres_test ficar pronto...")
	if !waitForPostgresReady("localhost", "65432", 60*time.Second) {
		fmt.Println("❌ postgres_test não ficou pronto no tempo esperado.")
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
	fmt.Println("✓ postgres_test está pronto!")

	// Configura variáveis de ambiente
	os.Setenv("POSTGRES_PORT", "65432")
	os.Setenv("POSTGRES_HOST", "localhost")
	os.Setenv("POSTGRES_USER", "postgres")
	os.Setenv("POSTGRES_PASSWORD", "postgres")
	os.Setenv("POSTGRES_DB", "contracts_manager_test")
	os.Setenv("POSTGRES_SSLMODE", "disable")

	// Executa os testes
	fmt.Println("\n▶ Executando testes Go com cobertura...")
	fmt.Println("─────────────────────────────────────────────────────────────")

	runCmd := "cd " + projectRoot + " && go test -v -cover ./..."
	testOutput, err := captureTestOutput(runCmd)

	fmt.Println("─────────────────────────────────────────────────────────────")

	// Exibe resumo de cobertura por pacote
	displayTestSummary(testOutput)

	if err != nil {
		fmt.Println("\n⚠ Alguns testes falharam.")
	} else {
		fmt.Println("\n✓ Todos os testes passaram com sucesso!")
	}

	fmt.Print("\nPressione ENTER para continuar...")
	bufio.NewReader(os.Stdin).ReadString('\n')

	fmt.Println("\n🛑 Apagando banco de testes...")
	runDockerComposeDownWithVolumes("postgres_test")
	fmt.Println("✓ Banco de testes removido!")
}

// captureTestOutput executa go test e captura a saída
func captureTestOutput(runCmd string) (string, error) {
	cmd := exec.Command("bash", "-c", runCmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Também captura em um pipe para processar depois
	output, _ := exec.Command("bash", "-c", runCmd).CombinedOutput()

	err := cmd.Run()
	return string(output), err
}

// displayTestSummary exibe um resumo dos testes por pacote
func displayTestSummary(output string) {
	results := parseTestOutput(output)

	if len(results) == 0 {
		return
	}

	// Exibe cada pacote com seu status e cobertura
	for _, info := range results {
		status := info["status"]
		coverage := info["coverage"]
		pkgName := info["name"]

		icon := "✅"
		if status == "FAIL" {
			icon = "❌"
		}

		if coverage != "" {
			// Remove "of statements" do coverage para ficar mais limpo
			coverage = strings.TrimSuffix(coverage, " of statements")
			fmt.Printf("%s %-20s - %s (coverage: %s)\n", icon, pkgName, status, coverage)
		} else {
			fmt.Printf("%s %-20s - %s\n", icon, pkgName, status)
		}
	}
}

// parseTestOutput extrai informações de cobertura por pacote da saída do go test
func parseTestOutput(output string) []map[string]string {
	results := []map[string]string{}

	lines := strings.Split(output, "\n")
	seen := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Procura por linhas que iniciam com ok ou FAIL
		// Exemplo: "ok  	Contracts-Manager/backend/domain	(cached)	coverage: 81.7% of statements"
		if !strings.HasPrefix(line, "ok") && !strings.HasPrefix(line, "FAIL") {
			continue
		}

		// Separa por tabulações e espaços
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		status := fields[0]
		pkgPath := fields[1]

		// Ignora pacotes que não têm testes
		if strings.Contains(pkgPath, "cmd/cli") || strings.Contains(pkgPath, "cmd/tools") || strings.Contains(pkgPath, "database") {
			continue
		}

		// Extrai o nome curto do pacote (última parte do path)
		parts := strings.Split(pkgPath, "/")
		pkgName := parts[len(parts)-1]

		// Evita duplicatas
		if seen[pkgName] {
			continue
		}
		seen[pkgName] = true

		// Procura por "coverage:" na linha e junta tudo depois dele
		coverage := ""
		for i := 0; i < len(fields); i++ {
			if fields[i] == "coverage:" && i+1 < len(fields) {
				// Junta "XX.X% of statements"
				coverageParts := []string{fields[i+1]}
				if i+2 < len(fields) {
					coverageParts = append(coverageParts, fields[i+2:]...)
				}
				coverage = strings.Join(coverageParts, " ")
				break
			}
		}

		result := map[string]string{
			"name":     pkgName,
			"path":     pkgPath,
			"status":   status,
			"coverage": coverage,
		}

		results = append(results, result)
	}

	return results
}
