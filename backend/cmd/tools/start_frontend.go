// Contracts-Manager/backend/cmd/tools/start_frontend.go

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

func startFrontend() {
	clearTerminal()
	fmt.Println("=== Iniciar Frontend ===\n ")

	// Descobre o diretório raiz do projeto
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		fmt.Println("❌ Erro: Não foi possível determinar o diretório do projeto")
		fmt.Print("\nPressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}

	// Navega para o diretório frontend (3 níveis acima: tools -> cmd -> backend -> raiz)
	backendRoot := filepath.Dir(filepath.Dir(filepath.Dir(filename)))
	projectRoot := filepath.Dir(backendRoot)
	frontendPath := filepath.Join(projectRoot, "frontend")

	fmt.Printf("📂 Diretório do frontend: %s\n\n", frontendPath)

	// Verifica se o diretório existe
	if _, err := os.Stat(frontendPath); os.IsNotExist(err) {
		fmt.Println("❌ Erro: Diretório do frontend não encontrado")
		fmt.Println("   Certifique-se de que a pasta 'frontend' existe no diretório raiz do projeto")
		fmt.Print("\nPressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}

	// Verifica se node_modules existe
	nodeModulesPath := filepath.Join(frontendPath, "node_modules")
	if _, err := os.Stat(nodeModulesPath); os.IsNotExist(err) {
		fmt.Println("⚠️  Dependências não instaladas. Instalando...")
		installCmd := exec.Command("npm", "install")
		installCmd.Dir = frontendPath
		installCmd.Stdout = os.Stdout
		installCmd.Stderr = os.Stderr

		if err := installCmd.Run(); err != nil {
			fmt.Printf("\n❌ Erro ao instalar dependências: %v\n ", err)
			fmt.Println("   Execute manualmente: cd frontend && npm install")
			fmt.Print("\nPressione ENTER para continuar...")
			bufio.NewReader(os.Stdin).ReadString('\n')
			return
		}
		fmt.Println("\n✅ Dependências instaladas com sucesso!\n ")
	}

	// Verifica se já está rodando
	if runtime.GOOS != "windows" {
		checkCmd := exec.Command("sh", "-c", "lsof -ti:8080")
		if output, _ := checkCmd.Output(); len(output) > 0 {
			fmt.Println("⚠️  Frontend já está rodando na porta 8080")
			fmt.Print("\nPressione ENTER para continuar...")
			bufio.NewReader(os.Stdin).ReadString('\n')
			return
		}
	}

	fmt.Println("🚀 Iniciando frontend em background...")
	fmt.Println("🌐 URL: http://localhost:8080")
	fmt.Println("\n💡 Use a opção 16 para parar o frontend")

	// Executa o frontend em background
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", "start", "/B", "npm", "run", "dev")
	} else {
		cmd = exec.Command("sh", "-c", "nohup npm run dev > /dev/null 2>&1 &")
	}
	cmd.Dir = frontendPath

	err := cmd.Start()
	if err != nil {
		fmt.Printf("\n❌ Erro ao executar frontend: %v\n", err)
		fmt.Print("\nPressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}

	// Aguarda um pouco para verificar se iniciou
	time.Sleep(3 * time.Second)

	// Verifica se está rodando
	if runtime.GOOS != "windows" {
		checkCmd := exec.Command("sh", "-c", "lsof -ti:8080")
		if output, _ := checkCmd.Output(); len(output) > 0 {
			fmt.Println("\n✅ Frontend iniciado com sucesso!")
		} else {
			fmt.Println("\n⚠️  Frontend pode não ter iniciado corretamente")
		}
	} else {
		fmt.Println("\n✅ Comando de inicialização enviado")
	}

	fmt.Print("\nPressione ENTER para continuar...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
