// Contracts-Manager/backend/cmd/tools/start_server.go

package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

func startServer() {
	clearTerminal()
	fmt.Println("=== Iniciar Servidor HTTP ===\n ")

	// Descobre o diretório raiz do projeto
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		fmt.Println("❌ Erro: Não foi possível determinar o diretório do projeto")
		if !skipClearTerminal {
			fmt.Print("\nPressione ENTER para continuar...")
		}
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
		if !skipClearTerminal {
			fmt.Print("\nPressione ENTER para continuar...")
		}
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}

	// Verifica se já está rodando
	if runtime.GOOS != "windows" {
		checkCmd := exec.Command("bash", "-c", "lsof -ti:3000")
		if output, _ := checkCmd.Output(); len(output) > 0 {
			fmt.Println("⚠️  Servidor já está rodando na porta 3000")
			if !skipClearTerminal {
				fmt.Print("\nPressione ENTER para continuar...")
			}
			bufio.NewReader(os.Stdin).ReadString('\n')
			return
		}
	}

	fmt.Println("🚀 Iniciando servidor HTTP em foreground (saída abaixo):")
	fmt.Println("📡 API: http://localhost:3000")
	fmt.Println("🔍 Health check: http://localhost:3000/health")
	fmt.Println("\n💡 Use a opção 22 para parar o servidor")
	fmt.Printf("\n O diretório do servidor é: %v \n ", serverPath)

	// Executa o servidor em background com nohup e log em backend.log (Linux/macOS)
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", "start", "/B", "go", "run", ".")
	} else {
		cmd = exec.Command("bash", "-c", "nohup go run . > server.log 2>&1 &")
	}
	cmd.Dir = serverPath

	err := cmd.Start()
	if err != nil {
		fmt.Printf("\n❌ Erro ao executar servidor: %v\n", err)
		if !skipClearTerminal {
			fmt.Print("\nPressione ENTER para continuar...")
		}
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}

	go func() {
		cmd.Wait()
	}()

	// Aguarda verificando se o servidor realmente subiu (health check)
	maxWait := 3 * time.Second
	start := time.Now()
	serverUp := false

	for {
		// Evita laço infinito
		if time.Since(start) > maxWait {
			break
		}

		// Faz uma chamada simples ao endpoint de health
		resp, err := http.Get("http://localhost:3000/health")
		if err == nil && resp.StatusCode == http.StatusOK {
			serverUp = true
			_ = resp.Body.Close()
			break
		}
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}

		time.Sleep(1 * time.Second)
	}

	if serverUp {
		fmt.Println("\n✅ Servidor iniciado com sucesso!")
	} else {
		fmt.Println("\n⚠️  Servidor pode não ter iniciado corretamente")
	}

	if !skipClearTerminal {
		fmt.Print("\nPressione ENTER para continuar...")
	}
	bufio.NewReader(os.Stdin).ReadString('\n')
}
