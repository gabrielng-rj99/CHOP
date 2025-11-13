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

	// 0. Verificar containers Docker
	mainRunning := isContainerRunning("contract_manager_postgres")
	testRunning := isContainerRunning("contract_manager_postgres_test")

	// Estado ideal: main UP + test OFF
	idealState := mainRunning && !testRunning

	// 1. Verificar variáveis de ambiente
	fmt.Println("\n1️⃣  Verificando variáveis de ambiente...")
	port, portSet := os.LookupEnv("POSTGRES_PORT")
	db, dbSet := os.LookupEnv("POSTGRES_DB")
	testDB, testDBSet := os.LookupEnv("TEST_DB")

	if !portSet {
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

	if !dbSet {
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

	if testDBSet && testDB == "1" {
		fmt.Println("   ⚠️  TEST_DB = 1 (modo de teste ativado)")
		fmt.Println("   📝 Isso está correto APENAS durante execução de testes")
		allGood = false
	} else {
		fmt.Println("   ✅ TEST_DB não definida (modo normal)")
	}

	// 3. Verificar arquivos críticos
	fmt.Println("\n2️⃣  Verificando arquivos críticos...")
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
	fmt.Println("\n3️⃣  Verificando lógica de detecção de banco...")
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

	if idealState && allGood {
		fmt.Println("║ ✅ VALIDAÇÃO 100% COMPLETA: Estado IDEAL alcançado!                       ║")
	} else if !allGood {
		fmt.Println("║ ❌ ERRO: Problema de configuração detectado                               ║")
		fmt.Println("╠═══════════════════════════════════════════════════════════════════════════╣")
		fmt.Println("║ Limpe as variáveis de ambiente se não estiver rodando testes              ║")
	} else {
		fmt.Println("║ ⚠️  AVISOS: Containers não estão no estado ideal                           ║")
	}

	fmt.Println("╠═══════════════════════════════════════════════════════════════════════════╣")
	fmt.Println("║                        📊 STATUS DOS CONTAINERS                           ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════════════════╣")

	if mainRunning {
		fmt.Println("║ ✅ Banco PRINCIPAL: RODANDO                                               ║")
	} else {
		fmt.Println("║ ❌ Banco PRINCIPAL: PARADO  (use opção 21 para iniciar)                   ║")
	}

	if testRunning {
		fmt.Println("║ ⚠️  Banco de TESTES: RODANDO ( Use a opção 91 para executar testes         ║")
		fmt.Println("║                              ou use opção 39 para parar o banco de teste) ║")
	} else {
		fmt.Println("║ ✅ Banco de TESTES: PARADO                                                ║")
	}

	fmt.Println("╚═══════════════════════════════════════════════════════════════════════════╝")

	fmt.Print("\nPressione ENTER para continuar...")
	fmt.Scanln()
}
