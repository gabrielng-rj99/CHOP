package main

import (
	"fmt"
	"os"
	"strings"
)

// ValidateDBSeparation valida que os bancos estão corretamente separados
func ValidateDBSeparation() {
	clearTerminal()
	fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║           VALIDAÇÃO DE SEPARAÇÃO DOS BANCOS DE DADOS                       ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")

	allGood := true
	hasWarnings := false

	// 1. Verificar containers Docker
	fmt.Println("\n1️⃣  Verificando containers Docker...")
	mainRunning := isContainerRunning("contract_manager_postgres")
	testRunning := isContainerRunning("contract_manager_postgres_test")

	if mainRunning {
		fmt.Println("   ✅ Banco PRINCIPAL está rodando (contract_manager_postgres)")
	} else {
		fmt.Println("   ⚠️  Banco PRINCIPAL não está rodando")
		hasWarnings = true
	}

	if testRunning {
		fmt.Println("   ⚠️  Banco de TESTES está rodando (contract_manager_postgres_test)")
		fmt.Println("   📝 Nota: Banco de testes deve ser usado APENAS para 'go test'")
		hasWarnings = true
	} else {
		fmt.Println("   ✅ Banco de TESTES não está rodando (correto para uso normal)")
	}

	// 2. Verificar variáveis de ambiente
	fmt.Println("\n2️⃣  Verificando variáveis de ambiente...")
	port := os.Getenv("POSTGRES_PORT")
	db := os.Getenv("POSTGRES_DB")
	testDB := os.Getenv("TEST_DB")

	if port == "" {
		fmt.Println("   ✅ POSTGRES_PORT não definida (usará 5432 por padrão)")
	} else if port == "5432" {
		fmt.Println("   ✅ POSTGRES_PORT = 5432 (banco principal)")
	} else if port == "65432" {
		fmt.Println("   ⚠️  POSTGRES_PORT = 65432 (banco de testes)")
		fmt.Println("   📝 Isso está correto APENAS durante execução de testes")
		allGood = false
	} else {
		fmt.Printf("   ❌ POSTGRES_PORT = %s (porta desconhecida)\n", port)
		allGood = false
	}

	if db == "" {
		fmt.Println("   ✅ POSTGRES_DB não definida (usará contracts_manager por padrão)")
	} else if db == "contracts_manager" {
		fmt.Println("   ✅ POSTGRES_DB = contracts_manager (banco principal)")
	} else if db == "contracts_manager_test" {
		fmt.Println("   ⚠️  POSTGRES_DB = contracts_manager_test (banco de testes)")
		fmt.Println("   📝 Isso está correto APENAS durante execução de testes")
		allGood = false
	} else {
		fmt.Printf("   ❌ POSTGRES_DB = %s (database desconhecido)\n", db)
		allGood = false
	}

	if testDB == "1" {
		fmt.Println("   ⚠️  TEST_DB = 1 (modo de teste ativado)")
		fmt.Println("   📝 Isso está correto APENAS durante execução de testes")
		allGood = false
	} else {
		fmt.Println("   ✅ TEST_DB não definida (modo normal)")
	}

	// 3. Verificar arquivos críticos
	fmt.Println("\n3️⃣  Verificando arquivos críticos...")
	criticalFiles := []string{
		"database/database.go",
		"cmd/tools/create_admin.go",
		"cmd/tools/launch_cli.go",
		"cmd/tools/init_main_db.go",
		"cmd/tools/init_test_db.go",
	}

	for _, file := range criticalFiles {
		if _, err := os.Stat(file); err == nil {
			fmt.Printf("   ✅ %s existe\n", file)
		} else {
			fmt.Printf("   ❌ %s NÃO encontrado\n", file)
			allGood = false
		}
	}

	// 4. Verificar conteúdo do database.go
	fmt.Println("\n4️⃣  Verificando lógica de detecção de banco...")
	content, err := os.ReadFile("database/database.go")
	if err != nil {
		fmt.Println("   ❌ Erro ao ler database.go")
		allGood = false
	} else {
		contentStr := string(content)

		if strings.Contains(contentStr, "65432") {
			fmt.Println("   ✅ Detecção de porta 65432 implementada")
		} else {
			fmt.Println("   ⚠️  Porta 65432 não mencionada em database.go")
		}

		if strings.Contains(contentStr, "contracts_manager_test") {
			fmt.Println("   ✅ Detecção de banco de testes implementada")
		} else {
			fmt.Println("   ⚠️  contracts_manager_test não mencionado")
		}

		if strings.Contains(contentStr, "contracts_manager") && !strings.Contains(contentStr, "contracts_manager_test") {
			fmt.Println("   ✅ Banco principal configurado")
		}
	}

	// 5. Resumo
	fmt.Println("\n╔═══════════════════════════════════════════════════════════════════════════╗")

	if !allGood && !hasWarnings {
		// Problemas de configuração (variáveis de ambiente erradas)
		fmt.Println("║ ❌ ERRO: Problema de configuração detectado                               ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
		fmt.Println("║                        📝 RECOMENDAÇÕES                                    ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
		fmt.Println("║ 1. Se estiver rodando testes: ignore os avisos                            ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║ 2. Se estiver usando CLI/Admin: limpe as variáveis:                       ║")
		fmt.Println("║    $ unset POSTGRES_PORT                                                  ║")
		fmt.Println("║    $ unset POSTGRES_DB                                                    ║")
		fmt.Println("║    $ unset TEST_DB                                                        ║")
	} else if allGood && hasWarnings {
		// Avisos (bancos não rodando ou teste rodando)
		fmt.Println("║ ⚠️  AVISOS: Configuração OK, mas há avisos sobre containers               ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
		fmt.Println("║                        📝 OBSERVAÇÕES                                      ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
		if !mainRunning {
			fmt.Println("║ • Banco PRINCIPAL não está rodando                                        ║")
			fmt.Println("║   Para usar CLI/Admin, rode: opção 11 no menu tools                      ║")
		}
		if testRunning {
			fmt.Println("║ • Banco de TESTES está rodando                                            ║")
			fmt.Println("║   Isso é normal durante 'go test', mas deve ser parado após testes       ║")
		}
	} else if !allGood && hasWarnings {
		// Ambos os problemas
		fmt.Println("║ ❌ MÚLTIPLOS PROBLEMAS DETECTADOS                                          ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
		fmt.Println("║ 1. Limpe as variáveis de ambiente (se não estiver rodando testes)         ║")
		fmt.Println("║ 2. Verifique os containers Docker (se precisar usar a aplicação)          ║")
	} else {
		// Tudo OK
		fmt.Println("║ ✅ VALIDAÇÃO COMPLETA: Separação de bancos está CORRETA!                  ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
		fmt.Println("║                          📋 REGRAS DE USO                                  ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
		fmt.Println("║ 🟢 Banco PRINCIPAL (porta 5432):                                          ║")
		fmt.Println("║    • Usar para: CLI, Admin, Desenvolvimento, Produção                     ║")
		fmt.Println("║    • Container: contract_manager_postgres                                 ║")
		fmt.Println("║    • Database: contracts_manager                                          ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║ 🔵 Banco de TESTES (porta 65432):                                         ║")
		fmt.Println("║    • Usar APENAS para: go test                                            ║")
		fmt.Println("║    • Container: contract_manager_postgres_test                            ║")
		fmt.Println("║    • Database: contracts_manager_test                                     ║")
		fmt.Println("║    • Comando: POSTGRES_PORT=65432 go test ./...                           ║")
	}

	fmt.Println("╚═══════════════════════════════════════════════════════════════════════════╝")

	fmt.Print("\nPressione ENTER para continuar...")
	fmt.Scanln()
}
