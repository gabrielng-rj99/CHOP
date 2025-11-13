// Contracts-Manager/backend/cmd/tools/start_server.go

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

func startServer() {
	clearTerminal()
	fmt.Println("=== Iniciar Servidor HTTP ===\n")

	// Descobre o diretório raiz do projeto
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		fmt.Println("❌ Erro: Não foi possível determinar o diretório do projeto")
		fmt.Print("\nPressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}

	// Navega para o diretório backend
	projectRoot := filepath.Dir(filepath.Dir(filepath.Dir(filename)))
	serverPath := filepath.Join(projectRoot, "cmd", "server")

	fmt.Printf("📂 Diretório do servidor: %s\n\n", serverPath)

	// Verifica se o diretório existe
	if _, err := os.Stat(serverPath); os.IsNotExist(err) {
		fmt.Println("❌ Erro: Diretório do servidor não encontrado")
		fmt.Print("\nPressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}

	// Verifica se já está rodando
	if runtime.GOOS != "windows" {
		checkCmd := exec.Command("sh", "-c", "lsof -ti:3000")
		if output, _ := checkCmd.Output(); len(output) > 0 {
			fmt.Println("⚠️  Servidor já está rodando na porta 3000")
			fmt.Print("\nPressione ENTER para continuar...")
			bufio.NewReader(os.Stdin).ReadString('\n')
			return
		}
	}

	fmt.Println("🚀 Iniciando servidor HTTP em background...")
	fmt.Println("📡 API: http://localhost:3000")
	fmt.Println("🔍 Health check: http://localhost:3000/health")
	fmt.Println("\n💡 Use a opção 14 para parar o servidor")

	// Executa o servidor em background
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", "start", "/B", "go", "run", "main.go")
	} else {
		cmd = exec.Command("sh", "-c", "nohup go run main.go > /dev/null 2>&1 &")
	}
	cmd.Dir = serverPath

	err := cmd.Start()
	if err != nil {
		fmt.Printf("\n❌ Erro ao executar servidor: %v\n", err)
		fmt.Print("\nPressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}

	// Aguarda um pouco para verificar se iniciou
	time.Sleep(2 * time.Second)

	// Verifica se está rodando
	if runtime.GOOS != "windows" {
		checkCmd := exec.Command("sh", "-c", "lsof -ti:3000")
		if output, _ := checkCmd.Output(); len(output) > 0 {
			fmt.Println("\n✅ Servidor iniciado com sucesso!")
		} else {
			fmt.Println("\n⚠️  Servidor pode não ter iniciado corretamente")
		}
	} else {
		fmt.Println("\n✅ Comando de inicialização enviado")
	}

	fmt.Print("\nPressione ENTER para continuar...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
