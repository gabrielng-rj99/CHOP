// Contracts-Manager/backend/cmd/tools/start_frontend.go

package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func startFrontend() {
	clearTerminal()
	fmt.Println("=== Iniciar Frontend ===\n ")

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

	// Navega para o diretório frontend (3 níveis acima: tools -> cmd -> backend -> raiz)
	backendRoot := filepath.Dir(filepath.Dir(filepath.Dir(filename)))
	projectRoot := filepath.Dir(backendRoot)
	frontendPath := filepath.Join(projectRoot, "frontend")

	fmt.Printf("📂 Diretório do frontend: %s\n\n", frontendPath)

	// Verifica se o diretório existe
	if _, err := os.Stat(frontendPath); os.IsNotExist(err) {
		fmt.Println("❌ Erro: Diretório do frontend não encontrado")
		fmt.Println("   Certifique-se de que a pasta 'frontend' existe no diretório raiz do projeto")
		if !skipClearTerminal {
			fmt.Print("\nPressione ENTER para continuar...")
		}
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
			if !skipClearTerminal {
				fmt.Print("\nPressione ENTER para continuar...")
			}
			bufio.NewReader(os.Stdin).ReadString('\n')
			return
		}
		fmt.Println("\n✅ Dependências instaladas com sucesso!\n ")
	}

	// Verifica se a porta 8080 está livre antes de iniciar
	if runtime.GOOS != "windows" {
		checkCmd := exec.Command("bash", "-c", "lsof -ti:8080")
		if output, _ := checkCmd.Output(); len(output) > 0 {
			fmt.Println("❌ Erro: A porta 8080 já está em uso.")
			fmt.Println("   Libere a porta 8080 antes de iniciar o frontend.")
			if !skipClearTerminal {
				fmt.Print("\nPressione ENTER para continuar...")
			}
			bufio.NewReader(os.Stdin).ReadString('\n')
			return
		}
	}

	// Exibe a versão do Node.js usada pelo processo após carregar NVM
	nodeVersionCmd := exec.Command("bash", "-c", "source $HOME/.nvm/nvm.sh && nvm use $(cat .nvmrc) && node -v")
	nodeVersionCmd.Dir = frontendPath
	nodeVersionOut, err := nodeVersionCmd.Output()
	if err == nil {
		fmt.Printf("🟢 Node.js version (via NVM): %s\n", strings.TrimSpace(string(nodeVersionOut)))
	} else {
		fmt.Println("⚠️  Não foi possível obter a versão do Node.js via NVM")
	}

	fmt.Println("🚀 Iniciando frontend...")
	fmt.Println("🌐 URL: http://localhost:8080")
	fmt.Println("\n💡 Use a opção 23 para parar o frontend")
	if !skipClearTerminal {
		fmt.Println("🟢 Logs do frontend serão exibidos abaixo:")
	}

	// Executa o frontend em background e printa logs em tempo real no terminal
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", "npm run dev")
	} else {
		cmd = exec.Command("bash", "-c", "source $HOME/.nvm/nvm.sh && nvm use $(cat .nvmrc) && npm run dev")
	}
	cmd.Dir = frontendPath

	stdoutPipe, pipeErr := cmd.StdoutPipe()
	if pipeErr != nil {
		fmt.Printf("\n❌ Erro ao criar pipe para stdout: %v\n", pipeErr)
		return
	}
	stderrPipe, pipeErr := cmd.StderrPipe()
	if pipeErr != nil {
		fmt.Printf("\n❌ Erro ao criar pipe para stderr: %v\n", pipeErr)
		return
	}

	if err = cmd.Start(); err != nil {
		fmt.Printf("\n❌ Erro ao executar frontend: %v\n", err)
		if !skipClearTerminal {
			fmt.Print("\nPressione ENTER para continuar...")
		}
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}

	// Printar logs em tempo real apenas se skipClearTerminal for falso
	if !skipClearTerminal {
		go func() {
			scanner := bufio.NewScanner(stdoutPipe)
			for scanner.Scan() {
				fmt.Println(scanner.Text())
			}
		}()
		go func() {
			scanner := bufio.NewScanner(stderrPipe)
			for scanner.Scan() {
				fmt.Println(scanner.Text())
			}
		}()
	}

	// Aguarda um tempo para o health check e logs iniciais
	time.Sleep(3 * time.Second)

	// Logs agora são mostrados direto no terminal pelo cmd.Stdout/cmd.Stderr

	// Aguarda verificando se o frontend realmente subiu (health check)
	maxWait := 3 * time.Second
	start := time.Now()
	frontendUp := false

	for {
		if time.Since(start) > maxWait {
			break
		}
		resp, err := http.Get("http://localhost:8080")
		if err == nil && resp.StatusCode == http.StatusOK {
			frontendUp = true
			_ = resp.Body.Close()
			break
		}
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Verifica se está rodando
	if frontendUp {
		fmt.Println("\n✅ Frontend iniciado com sucesso!")
	} else {
		fmt.Println("\n⚠️  Frontend pode não ter iniciado corretamente")
	}

	if !skipClearTerminal {
		fmt.Print("\nPressione ENTER para continuar...")
	}
	bufio.NewReader(os.Stdin).ReadString('\n')
}
